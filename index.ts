import { createCipheriv, createDecipheriv, createHash } from "crypto";
interface _webToken {
  secret?: string;
  cookieName?: string;
  iv?: string;
}

export class webToken<_Data> {
  private secret: string;
  private algorithm = "aes-256-cbc";
  private iv: string;
  private cookieName = "WebToken";
  private encryptedData?: string;
  private sessionData?: _Data;
  private request: Request;

  /** init.secret will replace the ENV variable WEB_TOKEN_SECRET */
  constructor(request: Request, init?: _webToken) {
    this.secret = init?.secret
      ? init.secret
      : (process.env.WEB_TOKEN_SECRET as string);
    if (!this.secret)
      throw new Error("set .env WEB_TOKEN_SECRET=<32 Random Char>");
    this.request = request;
    this.iv = process.env.WEB_TOKEN_IV || "1xD4R5TgHrRp09gF";
    this.cookieName = init?.cookieName ? init.cookieName : this.cookieName;
    this.iv = init?.iv ? init.iv : this.iv;
    try {
      this.sessionData = this.getCookie<_Data>();
    } catch (e) {
      //console.log(e);
      this.sessionData = undefined;
    }
  }
  public session() {
    return this.sessionData;
  }
  /** add or replace already setted data to the token */
  public updateData(data: { [key: string]: any }) { }
  /** create or reaplce entireley the token data */
  public setData(data: { [key: string]: any }) {
    const cipher = this.cipher();
    const encrypted =
      cipher.update(this.encodeData(data), "utf-8", "hex") +
      cipher.final("hex");
    this.encryptedData = encrypted;
    return encrypted;
  }
  public getData(data: string) {
    const decipher = this.decipher();
    const decrypted =
      decipher.update(data, "hex", "utf8") + decipher.final("utf8");
    return this.decodeData(decrypted);
  }
  public setCookie(
    response: Response,
    options?: { expire?: number; httpOnly: boolean; secure: boolean, path?: string }
  ) {
    if (!this.encryptedData)
      throw new Error("there is no data set to be send to cookie");
    response.headers.append(
      "Set-Cookie",
      `${this.cookieName}=${this.encryptedData}; Max-Age=${options?.expire || 3000
      }; ${options?.httpOnly ? "HttpOnly='true';" : ""} ${options?.secure ? "Secure='true';" : ""
      }path=${options?.path || "/"}`
    );
    return response;
  }
  private getCookie<_Data>() {
    const token = Object.assign(
      {},
      ...(this.request.headers
        .get("cookie")
        ?.split(";")
        .map((c) => {
          const _c = c.split("=");
          return {
            [_c[0].trim()]: _c[1],
          };
        }) || [])
    )[this.cookieName];
    if (!token) return;
    return this.getData(token) as _Data;
  }

  private decipher() {
    return createDecipheriv(
      this.algorithm,
      this.hashedSecret(),
      this.hashedIV()
    );
  }
  private cipher() {
    return createCipheriv(this.algorithm, this.hashedSecret(), this.hashedIV());
  }
  private encodeData(data: any) {
    return btoa(encodeURI(JSON.stringify(data)));
  }
  private decodeData(data: string) {
    return JSON.parse(decodeURI(atob(data)));
  }
  private hashedSecret() {
    const hashed = createHash("sha256")
      .update(this.secret)
      .digest("base64")
      .slice(0, 32);
    return hashed;
  }
  private hashedIV() {
    const hashed = createHash("sha256")
      .update(this.iv)
      .digest("base64")
      .slice(0, 16);
    return hashed;
  }
}
