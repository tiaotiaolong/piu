from flask import Blueprint,request,make_response,redirect
from app import pa_user
from functools import wraps

user_blueprint = Blueprint("user", __name__, url_prefix='/user')

token="jsi6de30uzxhaw1np9gvfl7roy5tcb82"

@user_blueprint.route('/login',methods=["POST"])
def user_login():
    if request.method=="POST":
        json_data = request.get_json()
        username = json_data['username']
        password = json_data['password']

        user=pa_user.find_one({"username":username,"password":password})
        if user:
            response=make_response({"code":200})

            response.headers['token']=token
            return response
        else:
            return {"code":201}

    return {"code": 203}

#装饰器函数，用来校验用户是否登录
def authenticate(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        _user=request.headers
        _user_token=_user.get("token")
        print(type(_user_token))
        #登录成功，就执行原来的函数
        if _user_token==token:
            return func(*args,**kwargs)
        return redirect('/login')

    return wrapper



@user_blueprint.route('/test')
@authenticate
def test():
    print(2222)
    return {"1":1}








