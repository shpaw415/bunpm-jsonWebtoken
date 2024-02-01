# json-webtoken

### Exemple

```TypeScript
import { webToken } from "bunpm/"
interface _User {
  username: string;
}

Bun.serve({
  fetch(req) {
    const cookie = new webToken<_User>(req, {
      cookieName: "customName",
    });
    const session = cookie.session();
    if (!session) {
      cookie.setData({
        username: "shpaw415",
      });
      return cookie.setCookie(new Response("not logged"), {
        expire: 3000,
        httpOnly: false,
        secure: true,
      });
    } else {
      return new Response(`Logged as ${session.username}`);
    }
  },
  port: 3000,
});
```

### ENV

- WEB_TOKEN_SECRET = Random 32 length String for securing the data (must be strong!)
- WEB_TOKEN_IV = Random string for radomize encryption (more secure but not mendatory)
# bunpm-jsonWebtoken
