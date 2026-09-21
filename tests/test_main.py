import runpy
from unittest import mock


def test_main_module_starts_uvicorn_with_expected_configuration():
    with mock.patch("uvicorn.run") as run:
        runpy.run_module("jwks_server.__main__", run_name="__main__")

    run.assert_called_once()
    args, kwargs = run.call_args
    assert kwargs == {"host": "localhost", "port": 8080}
    assert args[0].title == "FastAPI"
