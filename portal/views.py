from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from django.apps import apps

import gzip
import pickle
import json
import yaml
from datetime import datetime
import time
import sys
import os

# Create your views here.


def load_x_secret_yml() -> dict:
    with open(f"./portal/x_secret.yml", "r", encoding='utf-8') as _f:
        try:
            _yml = yaml.load(_f, Loader=yaml.FullLoader)
        except:
            pass  # 파일이 없거나, 정상적으로 로드를 못했을 경우 흘러들어 온다. 문자라도 보낼까?
    return _yml


def check_header(_headers: dict) -> tuple:
    check_list = ('X-Event', 'X-Delivery', 'X-Secret', 'X-Model')
    print(type(check_list), flush=True)
    # Check Essential Keys : NO KEYs case
    # 나중에는 가독성을 위해 반복문을 풀어주자
    for key in check_list:
        if key not in _headers.keys():
            err_msg = "NO " + key.replace("X-", "").upper()
            return 422, err_msg
    # Check Essential Keys : VALUE ERRORs case
    # 나중에는 가독성을 위해 반복문을 풀어주자
    for key in check_list:
        if _headers[key] is None:  # None 확인 여기서 미리 거쳐두어야 아래에서도 무결함
            err_msg = "FORBIDDEN"
            return 403, err_msg

    _x_secret = _headers.get('X-Secret')
    _x_model = _headers.get('X-Model')
    _x_event = _headers.get('X-Event')

    x_secret_in_yaml = load_x_secret_yml()
    if x_secret_in_yaml.get(_x_model, {}).get(_x_event, None) != _x_secret:
        err_msg = "FORBIDDEN"
        return 403, err_msg
    return None, None


@csrf_exempt
def hook(request):
    if request.method != 'POST':
        return HttpResponse("Bad Request", status=400)

    code, err_msg = check_header(request.headers)
    if err_msg:  # 약속되지 않은 헤더가 들어왔을 때. 잔디로 알림이라도 해야하나?
        return HttpResponse(err_msg, status=code)
    else:
        del code, err_msg

    x_delivery = request.headers.get('X-Delivery')
    # save headers
    os.makedirs("./data/header", exist_ok=True)
    with open(f"./data/header/{x_delivery}.json", "w") as _f:
        _f.write(json.dumps(dict(request.headers)))

    # save body
    os.makedirs("./data/body", exist_ok=True)
    with gzip.open(f"./data/body/{x_delivery}.str.utf8.bytes.gz", "wb") as _f:
        _f.write(request.body)
    ###### SAVE COMPLETE #######


    js_cont = request.body.decode('utf-8')
    print(type(js_cont), flush=True)
    print(js_cont, flush=True)
    print(len(js_cont), flush=True)
    #json.loads(js_cont)

    return HttpResponse("OK", status=200)