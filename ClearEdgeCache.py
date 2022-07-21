def _edgeClearTemp():

    appdata_location = os.environ.get('LOCALAPPDATA')
    _edgeTempDir = r"{0}\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC".format(
        appdata_location)
    _edgeAppData = r"{0}\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AppData".format(
        appdata_location)

    try:
        os.system("taskkill  /F /IM MicrosoftEdge.exe")
    except:
        pass
    try:
        os.system("taskkill  /F /IM dllhost.exe")
    except:
        pass
    if os.path.exists(_edgeTempDir):
        for directory in os.listdir(_edgeTempDir):
            if directory.startswith('#!'):
                shutil.rmtree(
                    os.path.join(_edgeTempDir, directory), ignore_errors=True)

    if os.path.exists(_edgeAppData):
        shutil.rmtree(_edgeAppData, ignore_errors=True)