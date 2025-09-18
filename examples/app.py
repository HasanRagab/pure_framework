from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse
from pure_framework.middleware import BaseMiddleware

app = PureFramework()


class ProtectMiddleware(BaseMiddleware):
    def process(self, req: IRequest, res: IResponse) -> None:
        """Process the request through the middleware."""
        api_key = req.get_header("X-API-KEY")
        if api_key != "secret":
            res.json({"error": "Unauthorized"}, status_code=401)
            return


@get("/hello", middlewares=[ProtectMiddleware()])
def hello_world(req: IRequest, res: IResponse) -> None:
    res.json({"message": "Hello, World!"})


@get("/users/:id")
def get_user(req: IRequest, res: IResponse, id: int) -> None:
    res.json({"user_id": id, "name": f"User {id}"})


@post("/users")
def create_user(req: IRequest, res: IResponse) -> None:
    user_data = req.json
    res.json({"created": user_data}, status_code=201)


if __name__ == "__main__":
    app.run()
