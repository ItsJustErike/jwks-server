# create a HTTP server using uvicorn on port 8080
# 'python -m jwks_server' to run server
import uvicorn

from jwks_server.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(
            app,
            host="localhost",
            port=8080
        )