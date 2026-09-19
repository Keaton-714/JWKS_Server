import app

def test_jwks_endpoint():

    client = app.app.test_client()
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data

def test_auth_endpoint():
    client = app.app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200