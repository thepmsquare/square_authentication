import os.path

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format
from uvicorn import run

from square_authentication.configuration import (
    config_int_host_port,
    config_str_host_ip,
    global_object_square_logger,
    config_str_module_name,
    config_str_ssl_key_file_path,
    config_str_ssl_crt_file_path,
)
from square_authentication.routes import core, utility

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(core.router)
app.include_router(utility.router)


@app.get("/")
@global_object_square_logger.async_auto_logger
async def root():
    output_content = get_api_output_in_standard_format(log=config_str_module_name)
    return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)


if __name__ == "__main__":
    try:
        if os.path.exists(config_str_ssl_key_file_path) and os.path.exists(
            config_str_ssl_crt_file_path
        ):
            run(
                app,
                host=config_str_host_ip,
                port=config_int_host_port,
                ssl_certfile=config_str_ssl_crt_file_path,
                ssl_keyfile=config_str_ssl_key_file_path,
            )
        else:
            run(
                app,
                host=config_str_host_ip,
                port=config_int_host_port,
            )

    except Exception as exc:
        global_object_square_logger.logger.critical(exc, exc_info=True)
