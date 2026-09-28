# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The on-demand review application.

Started for an operation and stopped afterwards. It has no scheduler, no queue
consumer and no inbound path from the deployment: its input is a file an
administrator uploaded, having carried it here deliberately.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .config import Config

log = logging.getLogger("redaction_manager.app")


def build_app(config: Config) -> FastAPI:
    app = FastAPI(title="FileEngine Offsite Redaction", version=__version__)
    app.state.config = config

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "service": "redaction_manager", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        problems = config.problems()
        if problems:
            return JSONResponse({"status": "not-ready", "problems": problems}, status_code=503)
        return {"status": "ready"}

    # The operation's routes arrive with the phases in the proposal:
    #   upload   — accept a request file a human carried here
    #   verify   — check each erasure_id against the retained chain (§4.2)
    #   review   — show volume FIRST, then the rows, for approval (§4.3)
    #   hold     — the cooling period (§4.4)
    #   execute  — delete every version of every approved key, prove it (§5)
    #
    # Nothing is mounted. An application that can destroy backup history and has
    # no routes is exactly as useful as it should be until its review is done.
    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    config = Config()
    for p in config.problems():
        log.warning("not ready: %s", p)
    log.info("review UI on %s:%d — stop this process when the operation is done",
             config.host, config.port)
    uvicorn.run(build_app(config), host=config.host, port=config.port)
