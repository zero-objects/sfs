import { createHash } from "crypto";
import { pathToFileURL } from "url";
import { join } from "path";
globalThis.nodeCrypto = { createHash };

const base = process.cwd();
const clientModule = await import(pathToFileURL(join(base, "node_modules/thinbus-srp/client.mjs")).href);
const serverModule = await import(pathToFileURL(join(base, "node_modules/thinbus-srp/server.mjs")).href);

const rfc5054 = {
  N_base10: "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
  g_base10: "2",
  k_base16: "5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
};
const C = clientModule.default(rfc5054.N_base10, rfc5054.g_base10, rfc5054.k_base16);
const S = serverModule.default(rfc5054.N_base10, rfc5054.g_base10, rfc5054.k_base16);

const username = "alice@ifyna.de";
const password = "correct horse battery staple";

const regClient = new C();
const salt = regClient.generateRandomSalt();
const verifier = regClient.generateVerifier(salt, username, password);

const client = new C();
client.step1(username, password);
const server = new S();
const B = server.step1(username, salt, verifier);
const cred = client.step2(salt, B);     // {A, M1}
const M2 = server.step2(cred.A, cred.M1);
const ok = client.step3(M2);
const Kc = client.getSessionKey();
const Ks = server.getSessionKey();

const introspect = (o) => Object.fromEntries(Object.entries(o).filter(([k,v]) => (typeof v==="string"||typeof v==="number")).map(([k,v])=>[k,String(v)]));

console.log(JSON.stringify({
  params: rfc5054, username, password, salt, verifier,
  A: cred.A, B, M1: cred.M1, M2, sessionKey_client: Kc, sessionKey_server: Ks, client_step3_ok: ok,
  client_internals: introspect(client),
  server_internals: introspect(server),
}, null, 2));
