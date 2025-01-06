import pickle
import re
import random
import string

from bbot.modules.deadly.ffuf import ffuf

class ffuf_shortnames(ffuf):
    watched_events = ["URL_HINT"]
    produced_events = ["URL_UNVERIFIED"]
    deps_pip = ["numpy"]
    flags = ["aggressive", "active", "iis-shortnames", "web-thorough"]
    meta = {
        "description": "Use ffuf in combination IIS shortnames",
        "created_date": "2022-07-05",
        "author": "@liquidsec",
    }

    options = {
        "wordlist": "",  # default is defined within setup function
        "wordlist_extensions": "",  # default is defined within setup function
        "max_depth": 1,
        "version": "2.0.0",
        "extensions": "",
        "ignore_redirects": True,
        "find_common_prefixes": False,
        "find_delimiters": True,
        "max_predictions": 250,
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "wordlist_extensions": "Specify wordlist to use when making extension lists",
        "max_depth": "the maximum directory depth to attempt to solve",
        "version": "ffuf version",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
        "ignore_redirects": "Explicitly ignore redirects (301,302)",
        "find_common_prefixes": "Attempt to automatically detect common prefixes and make additional ffuf runs against them",
        "find_delimiters": "Attempt to detect common delimiters and make additional ffuf runs against them",
        "max_predictions": "The maximum number of predictions to generate per shortname prefix"
    }

    deps_common = ["ffuf"]

    in_scope_only = True

    def generate_templist(self, prefix, shortname_type):
        virtual_file = []
        
        for prediction, score in self.predict(prefix, self.max_predictions, model=shortname_type):
            self.debug(f"Got prediction: [{prediction}] from prefix [{prefix}] with score [{score}]")
            virtual_file.append(prediction)
        virtual_file.append(self.canary)
        return self.helpers.tempfile(virtual_file, pipe=False), len(virtual_file)

    def predict(self,prefix,n=25,model="endpoint"):
        predictor_name = f"{model}_predictor"
        predictor = getattr(self, predictor_name)
        return predictor.predict(prefix, n)

    @staticmethod
    def find_common_prefixes(strings, minimum_set_length=4):
        prefix_candidates = [s[:i] for s in strings if len(s) == 6 for i in range(3, 6)]
        frequency_dict = {item: prefix_candidates.count(item) for item in prefix_candidates}
        frequency_dict = {k: v for k, v in frequency_dict.items() if v >= minimum_set_length}
        prefix_list = list(set(frequency_dict.keys()))

        found_prefixes = set()
        for prefix in prefix_list:
            prefix_frequency = frequency_dict[prefix]
            is_substring = False

            for k, v in frequency_dict.items():
                if prefix != k:
                    if prefix in k:
                        is_substring = True
            if not is_substring:
                found_prefixes.add(prefix)
            else:
                if prefix_frequency > v and (len(k) - len(prefix) == 1):
                    found_prefixes.add(prefix)
        return list(found_prefixes)

    async def setup(self):
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist_extensions = self.config.get("wordlist_extensions", "")
        if not wordlist_extensions:
            wordlist_extensions = f"{self.helpers.wordlist_dir}/raft-small-extensions-lowercase_CLEANED.txt"
        self.debug(f"Using [{wordlist_extensions}] for shortname candidate extension list")
        self.wordlist_extensions = await self.helpers.wordlist(wordlist_extensions)
        self.ignore_redirects = self.config.get("ignore_redirects")
        self.max_predictions = self.config.get("max_predictions")
    
        endpoint_model = f"{self.helpers.wordlist_dir}/endpoints.pred"
        directory_model = f"{self.helpers.wordlist_dir}/directories.pred"

        class MinimalWordPredictor:
            def __init__(self):
                self.word_frequencies = {}

            def predict(self, prefix, top_n):
                prefix = prefix.lower()
                matches = [(word, freq) for word, freq in self.word_frequencies.items() 
                        if word.startswith(prefix)]
                
                if not matches:
                    return []

                matches.sort(key=lambda x: x[1], reverse=True)
                matches = matches[:top_n]
                
                max_freq = matches[0][1]
                return [(word, freq/max_freq) for word, freq in matches]

        class CustomUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                if name == 'MinimalWordPredictor':
                    return MinimalWordPredictor
                return super().find_class(module, name)

        self.debug(f"Loading endpoint model from: {endpoint_model}")
        with open(endpoint_model, 'rb') as f:
            unpickler = CustomUnpickler(f)
            self.endpoint_predictor = unpickler.load()

        self.debug(f"Loading directory model from: {directory_model}")
        with open(directory_model, 'rb') as f:
            unpickler = CustomUnpickler(f)
            self.directory_predictor = unpickler.load()


        self.per_host_collection = {}
        self.shortname_to_event = {}
        return True

    def build_extension_list(self, event):
        used_extensions = []
        extension_hint = event.parsed_url.path.rsplit(".", 1)[1].lower().strip()
        if len(extension_hint) == 3:
            with open(self.wordlist_extensions) as f:
                for l in f:
                    l = l.lower().lstrip(".")
                    if l.lower().startswith(extension_hint):
                        used_extensions.append(l.strip())
            return used_extensions
        else:
            return [extension_hint]

    def find_delimiter(self, hint):
        delimiters = ["_", "-"]
        for d in delimiters:
            if d in hint:
                if not hint.startswith(d) and not hint.endswith(d):
                    return d, hint.split(d)[0], hint.split(d)[1]
        return None

    async def filter_event(self, event):
        if event.parent.type != "URL":
            return False, "its parent event is not of type URL"
        return True

    async def handle_event(self, event):
        filename_hint = re.sub(r"~\d", "", event.parsed_url.path.rsplit(".", 1)[0].split("/")[-1]).lower()

        if "shortname-endpoint" in event.tags:
            shortname_type = "endpoint"
        elif "shortname-directory" in event.tags:
            shortname_type = "directory"
        else:
            self.error("ffuf_shortnames received URL_HINT without proper 'shortname-' tag")
            return

        host = f"{event.parent.parsed_url.scheme}://{event.parent.parsed_url.netloc}/"
        if host not in self.per_host_collection.keys():
            self.per_host_collection[host] = [(filename_hint, event.parent.data)]

        else:
            self.per_host_collection[host].append((filename_hint, event.parent.data))

        self.shortname_to_event[filename_hint] = event

        root_stub = "/".join(event.parsed_url.path.split("/")[:-1])
        root_url = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}{root_stub}/"

        if shortname_type == "endpoint":
            used_extensions = self.build_extension_list(event)

        if len(filename_hint) == 6:
            tempfile, tempfile_len = self.generate_templist(filename_hint, shortname_type)
            self.verbose(
                f"generated temp word list of size [{str(tempfile_len)}] for filename hint: [{filename_hint}]"
            )

        else:
            tempfile = self.helpers.tempfile([filename_hint], pipe=False)
            tempfile_len = 1

        if tempfile_len > 0:
            if shortname_type == "endpoint":
                for ext in used_extensions:
                    async for r in self.execute_ffuf(tempfile, root_url, suffix=f".{ext}"):
                        await self.emit_event(
                            r["url"],
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=[f"status-{r['status']}"],
                            context=f"{{module}} brute-forced {ext.upper()} files at {root_url} and found {{event.type}}: {{event.data}}",
                        )

            elif shortname_type == "directory":
                async for r in self.execute_ffuf(tempfile, root_url, exts=["/"]):
                    r_url = f"{r['url'].rstrip('/')}/"
                    await self.emit_event(
                        r_url,
                        "URL_UNVERIFIED",
                        parent=event,
                        tags=[f"status-{r['status']}"],
                        context=f"{{module}} brute-forced directories at {r_url} and found {{event.type}}: {{event.data}}",
                    )

        if self.config.get("find_delimiters"):
            if "shortname-directory" in event.tags:
                delimiter_r = self.find_delimiter(filename_hint)
                if delimiter_r:
                    delimiter, prefix, partial_hint = delimiter_r
                    self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                    tempfile, tempfile_len = self.generate_templist(partial_hint, "directory")
                    ffuf_prefix = f"{prefix}{delimiter}"
                    async for r in self.execute_ffuf(tempfile, root_url, prefix=ffuf_prefix, exts=["/"]):
                        await self.emit_event(
                            r["url"],
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=[f"status-{r['status']}"],
                            context=f'{{module}} brute-forced directories with detected prefix "{ffuf_prefix}" and found {{event.type}}: {{event.data}}',
                        )

            elif "shortname-endpoint" in event.tags:
                for ext in used_extensions:
                    delimiter_r = self.find_delimiter(filename_hint)
                    if delimiter_r:
                        delimiter, prefix, partial_hint = delimiter_r
                        self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                        tempfile, tempfile_len = self.generate_templist(partial_hint, "endpoint")
                        ffuf_prefix = f"{prefix}{delimiter}"
                        async for r in self.execute_ffuf(tempfile, root_url, prefix=ffuf_prefix, suffix=f".{ext}"):
                            await self.emit_event(
                                r["url"],
                                "URL_UNVERIFIED",
                                parent=event,
                                tags=[f"status-{r['status']}"],
                                context=f'{{module}} brute-forced {ext.upper()} files with detected prefix "{ffuf_prefix}" and found {{event.type}}: {{event.data}}',
                            )

    async def finish(self):

        if self.config.get("find_common_prefixes"):
            per_host_collection = dict(self.per_host_collection)
            self.per_host_collection.clear()

            for host, hint_tuple_list in per_host_collection.items():
                hint_list = [x[0] for x in hint_tuple_list]

                common_prefixes = self.find_common_prefixes(hint_list)
                for prefix in common_prefixes:
                    self.verbose(f"Found common prefix: [{prefix}] for host [{host}]")
                    for hint_tuple in hint_tuple_list:
                        hint, url = hint_tuple
                        if hint.startswith(prefix):

                            if "shortname-endpoint" in self.shortname_to_event[hint].tags:
                                shortname_type = "endpoint"
                            elif "shortname-directory" in self.shortname_to_event[hint].tags:
                                shortname_type = "directory"
                            else:
                                self.error("ffuf_shortnames received URL_HINT without proper 'shortname-' tag")
                                continue


                            partial_hint = hint[len(prefix) :]

                            # safeguard to prevent loading the entire wordlist
                            if len(partial_hint) > 0:
                                tempfile, tempfile_len = self.generate_templist(partial_hint, shortname_type)

                                if "shortname-directory" in self.shortname_to_event[hint].tags:
                                    self.verbose(
                                        f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix} and partial_hint: {partial_hint}"
                                    )

                                    async for r in self.execute_ffuf(tempfile, url, prefix=prefix, exts=["/"]):
                                        await self.emit_event(
                                            r["url"],
                                            "URL_UNVERIFIED",
                                            parent=self.shortname_to_event[hint],
                                            tags=[f"status-{r['status']}"],
                                            context=f'{{module}} brute-forced directories with common prefix "{prefix}" and found {{event.type}}: {{event.data}}',
                                        )
                                elif shortname_type == "endpoint":
                                    used_extensions = self.build_extension_list(self.shortname_to_event[hint])

                                    for ext in used_extensions:
                                        self.verbose(
                                            f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix}, extension: .{ext}, and partial_hint: {partial_hint}"
                                        )
                                        async for r in self.execute_ffuf(
                                            tempfile, url, prefix=prefix, suffix=f".{ext}"
                                        ):
                                            await self.emit_event(
                                                r["url"],
                                                "URL_UNVERIFIED",
                                                parent=self.shortname_to_event[hint],
                                                tags=[f"status-{r['status']}"],
                                                context=f'{{module}} brute-forced {ext.upper()} files with common prefix "{prefix}" and found {{event.type}}: {{event.data}}',
                                            )
