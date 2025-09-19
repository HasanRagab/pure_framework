from pure_framework import PureFramework, get
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig


@get("/hello/:name")
def hello_name(req: IRequest, res: IResponse) -> None:
    name = req.params.get("name", "wtf")
    res.json({"message": f"Hello, {name}!"})


app = PureFramework()
config = ApplicationConfig(host="localhost", port=4000, debug=True)
app.run(config)
