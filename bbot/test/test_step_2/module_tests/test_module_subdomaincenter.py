from .base import ModuleTestBase


class TestSubdomainCenter(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.subdomain.center/?domain=blacklanternsecurity.com",
            json=["asdf.blacklanternsecurity.com", "zzzz.blacklanternsecurity.com"],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
