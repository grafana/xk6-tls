import { check, sleep } from "k6";
import tls from "k6/x/tls";

const DOMAINS = [
    "quickpizza.grafana.com",
    "platform.tt02.altinn.no",
    "am.ui.tt02.altinn.no",
    "platform.at23.altinn.cloud",
    "skm.apps.altinn.no",
];

export default async function () {
    for (const domain of DOMAINS) {
        let cert = null;

        try {
            cert = await tls.getCertificate(domain, {
                insecureSkipVerify: false,
                serverName: domain,
            });
        } catch (error) {
            console.error(`${domain}: TLS failed: ${error}`);
        }

        check(cert, {
            [`${domain}: certificate retrieved`]: (c) => !!c,
        });

        if (cert) {
            console.log(
                `${domain}: subject=${cert.subject.commonName}, ` +
                `issuer=${cert.issuer.commonName}, ` +
                `expires=${new Date(cert.expires).toISOString()}`
            );
        }

        sleep(1);
    }
}