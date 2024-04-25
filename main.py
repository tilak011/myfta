# main.py
from fastapi import FastAPI
# from pydantic import BaseModel
from werkzeug.exceptions import HTTPException
from vulnerability_detection_functions import *

app = FastAPI()
@app.get("/")
async def read_root():
    return {"message": "Welcome to Vulnerability Detection API"}

@app.post("/test_sql_injection")
async def test_sql_injection_api(url: str, vulnerable_parameter: str):
    try:
        result, message = test_sql_injection(url, vulnerable_parameter)
        return {"result": result, "message": message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error testing SQL injection: {str(e)}")

@app.get("/test_xss")
async def test_xss_api(url: str):
    try:
        if test_xss(url):
            return {"vulnerability_detected": True, "message": "XSS vulnerability detected."}
        else:
            return {"vulnerability_detected": False, "message": "No evidence of XSS vulnerability."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error testing XSS: {str(e)}")

@app.get("/test_directory_listing_api")
async def test_directory_listing_api(url: str):
    try:
        result, message = check_directory_listing(url)
        return {"result": result, "message": message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error testing directory listing: {str(e)}")

@app.get("/test_ssi_injection")
async def test_ssi_injection_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_ssi_injection(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_session_fixation")
async def test_session_fixation_api():
    url = "https://testphp.vulnweb.com/"
    session_id = "attacker_session_id"
    result, message = test_session_fixation(url, session_id)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_command_injection")
async def test_command_injection_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_command_injection(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_ldap_injection")
async def test_ldap_injection_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_ldap_injection(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_object_injection")
async def test_object_injection_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_object_injection(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_path_traversal")
async def test_path_traversal_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_path_traversal(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.get("/test_sql_injection")
async def test_sql_injection_api():
    url = "https://testphp.vulnweb.com/"
    result, message = test_sql_injection(url)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}


@app.get("/test_default_credentials")
async def test_default_credentials_api(default_username: str, default_password: str):
    url = "https://testphp.vulnweb.com/"
    result, message = test_default_credentials(url, default_username, default_password)
    if result:
        return {"vulnerability_detected": True, "message": message}
    else:
        return {"vulnerability_detected": False, "message": message}

@app.post("/test_csrf_api")
async def test_csrf_api(url: str, csrf_token: str):
    try:
        result, message = test_csrf(url, csrf_token)
        return {"result": result, "message": message}
    except HTTPException as http_err:
        raise http_err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {err}")

@app.post("/test_idor_api")
async def test_idor_api(url: str):
    try:
        result, message = test_idor(url)
        return {"result": result, "message": message}
    except HTTPException as http_err:
        raise http_err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {err}")

@app.post("/test_broken_authentication_api")
async def test_broken_authentication_api(url: str, username: str, password: str):
    try:
        result, message = test_broken_authentication(url, username, password)
        return {"result": result, "message": message}
    except HTTPException as http_err:
        raise http_err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {err}")

@app.post("/test_sensitive_data_exposure_api")
async def test_sensitive_data_exposure_api(url: str):
    try:
        result, message = test_sensitive_data_exposure(url)
        return {"result": result, "message": message}
    except HTTPException as http_err:
        raise http_err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {err}")