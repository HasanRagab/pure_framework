from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse

app = PureFramework()

@get('/hello')
def hello_world(req: IRequest, res: IResponse) -> None:
    res.json({'message': 'Hello, World!'})

@get('/users/:id')
def get_user(req: IRequest, res: IResponse, id: int) -> None:
    # Automatic parameter injection and type conversion
    res.json({'user_id': id, 'name': f'User {id}'})

@post('/users')
def create_user(req: IRequest, res: IResponse) -> None:
    user_data = req.json
    res.json({'created': user_data}, status_code=201)

if __name__ == '__main__':
    app.run()