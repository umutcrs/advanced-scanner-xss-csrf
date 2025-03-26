Object.defineProperty(exports, "__esModule", { value: true });
exports.Input = exports.Artifact = exports.ArtifactVerificationOptions_ObserverTimestampOptions = exports.ArtifactVerificationOptions_TlogIntegratedTimestampOptions = exports.ArtifactVerificationOptions_TimestampAuthorityOptions = exports.ArtifactVerificationOptions_CtlogOptions = exports.ArtifactVerificationOptions_TlogOptions = exports.ArtifactVerificationOptions = exports.PublicKeyIdentities = exports.CertificateIdentities = exports.CertificateIdentity = void 0;
/* eslint-disable */
const sigstore_bundle_1 = require("./sigstore_bundle");
const sigstore_common_1 = require("./sigstore_common");
const sigstore_trustroot_1 = require("./sigstore_trustroot");
exports.CertificateIdentity = {
    fromJSON(object) {
        return {
            issuer: isSet(object.issuer) ? globalThis.String(object.issuer) : "",
            san: isSet(object.san) ? sigstore_common_1.SubjectAlternativeName.fromJSON(object.san) : undefined,
            oids: globalThis.Array.isArray(object?.oids)
                ? object.oids.map((e) => sigstore_common_1.ObjectIdentifierValuePair.fromJSON(e))
                : [],
        };
    },
};
