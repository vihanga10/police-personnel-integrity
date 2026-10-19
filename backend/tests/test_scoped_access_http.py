from scoped_access_http_fixture import checks

def test_actual_https_server_login_and_complete_scope_matrix(tmp_path):
    result=checks(tmp_path)
    assert len(result)==16 and len(set(result))==16
