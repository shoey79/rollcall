"""A test pack for the password scan: files with known fake passwords (generic names only), plus
look-alikes that must not be reported. make_corpus(root) writes it and returns the fake passwords."""
import base64
import os
import shutil
import zipfile


def make_corpus(root):
    shutil.rmtree(root, ignore_errors=True)
    SECRETS = []
    def S(v):
        SECRETS.append(v); return v
    def w(rel, text, enc="utf-8"):
        p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(text.encode(enc) if isinstance(text, str) else text)
    
    w("Users/admin/Desktop/notes.txt", f"""Shopping list
    wifi password: {S('Tr0ub4dor&3x')}
    The password is {S('Winter2031!')}
    password is required for the portal
    Password: Stored in the vault
    pin: 1234
    """)
    w("Users/admin/Documents/Server Passwords.xlsx.txt", "decoy, not a real xlsx\n")
    w("Users/admin/Documents/deploy.ps1", f"""$pw = ConvertTo-SecureString "{S('Depl0y-Pass#1')}" -AsPlainText -Force
    $cred = ConvertTo-SecureString $secret -AsPlainText -Force
    $x = ConvertTo-SecureString -AsPlainText -Force -String '{S('Str1ng-Form!')}'
    New-ADUser -Name svc_backup -AccountPassword (Read-Host -AsSecureString)
    Connect-Thing -Server server.example.local -Password "{S('ParamPw-77')}"
    Connect-Thing -Password $Password
    $Password = "{S('VarPass-2031')}"
    $apiKey = $env:API_KEY
    net use Z: \\\\SRV01\\share {S('NetUsePw9')} /user:CONTOSO\\admin
    net use \\\\SRV01\\ipc$ /user:CONTOSO\\svc_backup {S('NetUse2Pw!')}
    net use Y: \\\\SRV01\\data * /user:CONTOSO\\admin
    net user localadmin {S('LocalAdm1n!')} /add
    net user admin /domain
    """)
    w("Users/admin/Documents/app.config", f"""<?xml version="1.0"?>
    <configuration>
      <connectionStrings>
        <add name="Main" connectionString="Server=SRV01;Database=Sales;User Id=svc_sql;Password={S('SqlConn#Pw1')};" />
        <add name="Integrated" connectionString="Server=SRV01;Database=Sales;Integrated Security=true" />
      </connectionStrings>
      <appSettings>
        <add key="SmtpPassword" value="{S('SmtpVal!42')}" />
        <add key="PasswordExpiryDays" value="90" />
      </appSettings>
      <ServicePassword>{S('ElemPw-5150')}</ServicePassword>
      <PasswordPolicy>Strong</PasswordPolicy>
      <Password>${{DB_PASS}}</Password>
    </configuration>
    """)
    w("Users/admin/Documents/sub/.env", f"""DB_HOST=server.example.local
    DB_PASSWORD={S('letmeinplease')}
    API_KEY="{S('k3y-ABCDEF123456')}"
    SECRET_KEY=
    REDIS_PASSWORD=changeme_{S('Rx9')}
    EMPTY_PASSWORD=""
    TOKEN=null
    """)
    w("Users/admin/Documents/sub/settings.py", f"""PASSWORD = os.environ["DB_PASSWORD"]
    password = get_password()
    password = config.db.password
    SECRET = "{S('PySecret-8812')}"
    """)
    w("Users/admin/Documents/links.md", f"""- Backup portal: https://admin:{S('UrlPw-6731')}@server.example.local/backup
    - Repo: git@github.com:example/example.git
    - Template: https://user:${{PASS}}@server.example.local
    """)
    w("Users/admin/Documents/history/ConsoleHost_history.txt", f"""mysql -u root -p{S('MyRootPw7')} sales
    mysql -u root -p sales
    sshpass -p '{S('SshPassPw3')}' ssh admin@SRV01
    curl -u admin:{S('CurlPw-4411')} https://server.example.local/api
    """)
    w("Users/admin/Documents/cloud.txt", f"""aws_access_key_id = {S('AKIA' + 'Z7Q2W3E4R5T6Y7U8')}
    example key {'AKIA' + 'IOSFODNN7EXAMPLE'}
    gh = {S('ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8')}
    slack {S('xox' + 'b-1234567890-abcdefghij')}
    DefaultEndpointsProtocol=https;AccountName=example;AccountKey={S('QWxhZGRpbjpv' + 'cGVuIHNlc2FtZQ0123456789abcd==')};EndpointSuffix=core.windows.net
    """)
    w("Win/Panther/unattend.xml", f"""<unattend>
     <UserAccounts>
      <AdministratorPassword>
       <Value>{S('Answ3rFile-Adm!')}</Value>
       <PlainText>true</PlainText>
      </AdministratorPassword>
     </UserAccounts>
     <AutoLogon><Password><Value></Value></Password></AutoLogon>
    </unattend>
    """)
    w("SYSVOL/Policies/{31B2F340}/Machine/Preferences/Groups/Groups.xml",
      f'<Groups><User name="admin"><Properties action="U" cpassword="{S("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw")}" userName="admin"/></User>'
      '<User name="x"><Properties cpassword="" userName="x"/></User></Groups>\n')
    w("Users/admin/Documents/utf16.ini", f"[db]\r\npassword={S('Utf16Pw-99')}\r\n", "utf-16")
    w("Users/admin/Documents/browser_export.csv", f"name,url,username,password\nexample,https://example.local,admin,{S('CsvRowPw#5')}\n")
    w("Users/admin/.pgpass", f"server.example.local:5432:sales:svc_sql:{S('PgPassPw-1')}\n# comment:a:b:c:d\n")
    w("Users/admin/.netrc", f"machine server.example.local login admin password {S('NetrcPw-22')}\n")
    w("Users/admin/node_modules/pkg/config.json", f'{{"password": "{S("ShouldBeSkipped1")}"}}\n')
    w("Users/admin/Documents/binary.dat.txt", b"\x00\x01password=Binary1234\x00")
    w("Users/admin/Documents/readme.txt", "Change your password every 90 days. Passwords must be 12 characters.\n")
    w("Users/admin/Documents/web.json", '{"passwordMinLength": 12, "password": "", "passwordHint": "pet name", "token": "********"}\n')
    # PuTTY and private keys (no real key material: just enough structure)
    w("Users/admin/.ssh/old.ppk", "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: test\n")
    w("Users/admin/.ssh/locked.ppk", "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: aes256-cbc\n")
    w("Users/admin/.ssh/id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n")
    w("Users/admin/.ssh/id_enc", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABC\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
    def osshkey(cipher):
        c = cipher.encode(); raw = b"openssh-key-v1\0" + len(c).to_bytes(4, "big") + c + b"\0" * 40
        b = base64.b64encode(raw).decode()
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(b[i:i+70] for i in range(0, len(b), 70)) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    w("Users/admin/.ssh/id_ed25519", osshkey("none"))
    w("Users/admin/.ssh/id_locked", osshkey("aes256-ctr"))
    # Office files
    def docx(rel, paras):
        p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        body = "".join("<w:p>" + "".join(f"<w:r><w:t>{r}</w:t></w:r>" for r in para) + "</w:p>" for para in paras)
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("word/document.xml", f'<w:document><w:body>{body}</w:body></w:document>')
    docx("Users/admin/Documents/Handover.docx", [["Handover notes"], ["Router admin "], ["Pass", "word: ", S("D0cxRouter!")], ["Nothing here"]])
    def xlsx(rel, strings):
        p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        sst = "".join(f"<si><t>{s}</t></si>" for s in strings)
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("xl/sharedStrings.xml", f'<sst>{sst}</sst>')
    xlsx("Users/admin/Documents/Accounts list.xlsx", ["System", "Username", "Password", "SRV01", "admin", S("XlsxCellPw#8")])
    xlsx("Users/admin/Documents/My Passwords.xlsx", ["Site", "Notes"])
    w("Users/admin/Documents/Logins 2031.doc", b"\xd0\xcf\x11\xe0 binary doc")
    w("Users/admin/Documents/password reset procedure.docx.txt", "decoy\n")
    w("Users/admin/Documents/Meine Kennwörter.txt", "Liste\n")
    return SECRETS
