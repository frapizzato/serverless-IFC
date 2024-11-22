import requests

def handle(req):
    """handle a request to the function
    Args:
        req (str): request body
    """
    gateway_url = "http://gateway.openfaas:8080/function/uppercase"
    response = requests.post(gateway_url, data=req)
    
    return response.text
