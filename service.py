"""
[EN]    CAdES (CMS) signing service using a PKCS#12 certificate pre-imported into the cache.

        Usage flow:
         1. Import the certificate ONCE:
              POST /solidsign/dsig/certificates/pkcs12/import
              Body (multipart): pfxCertificate=<file.pfx>, pfxPassword=<base64-password>
            Response: { "id": "<uuid>", "alias": "...", "expirationDate": "..." }
         2. Set the returned UUID in SOLIDSIGN_CERT_ID (.env).
         3. On every signing request, only the UUID is sent as "pfxCode".

[PT-BR] Serviço de assinatura CAdES (CMS) utilizando certificado PKCS#12 pré-importado na cache.

        Fluxo de uso:
         1. Importe o certificado UMA VEZ:
              POST /solidsign/dsig/certificates/pkcs12/import
              Body (multipart): pfxCertificate=<arquivo.pfx>, pfxPassword=<senha-base64>
            Resposta: { "id": "<uuid>", "alias": "...", "expirationDate": "..." }
         2. Configure o UUID retornado em SOLIDSIGN_CERT_ID (.env).
         3. A cada requisição de assinatura, apenas o UUID é enviado como "pfxCode".
"""

import io
import logging
import os
import time
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class CmsPkcs12Service:

    def __init__(self):
        self.base_url = os.getenv("SOLIDSIGN_API_BASE_URL", "").rstrip("/")
        self.authorization = os.getenv("SOLIDSIGN_API_AUTHORIZATION", "")
        self.profile = os.getenv("SOLIDSIGN_SIG_PROFILE", "ADRB")
        self.hash_algorithm = os.getenv("SOLIDSIGN_SIG_HASH_ALGORITHM", "SHA256")
        self.signature_packaging = os.getenv("SOLIDSIGN_SIG_PACKAGING", "ENVELOPING")
        self.policy_version = os.getenv("SOLIDSIGN_SIG_POLICY_VERSION", "")

    # ─── Batch endpoint (reads from local folder, properties used) ────────────

    def sign_pkcs12(self, files: List[Path], cert_id: str, output_dir: str) -> Optional[str]:
        """
        [EN]    Signs the given files via CAdES using the UUID of the pre-imported certificate.
        [PT-BR] Assina os arquivos informados via CAdES usando o UUID do certificado pré-importado.
        """
        logger.info("Starting CAdES PKCS12 signing for %d file(s) using certId=%s.", len(files), cert_id)
        sign_url = self.base_url + "/solidsign/dsig/cms/sign-pkcs12"
        headers = {"Authorization": self.authorization}

        opened = []
        req_files: dict = {}
        try:
            for i, f in enumerate(files):
                fh = open(f, "rb")
                opened.append(fh)
                req_files[f"document[{i}]"] = (f.name, fh, "application/octet-stream")

            data = {
                "pfxCode": cert_id,
                "profile": self.profile,
                "hashAlgorithm": self.hash_algorithm,
                "signaturePackaging": self.signature_packaging,
            }
            if self.policy_version:
                data["policyVersion"] = self.policy_version

            resp = requests.post(sign_url, headers=headers, files=req_files, data=data, timeout=120)
            resp.raise_for_status()

            zip_bytes = self._download_and_zip(resp.json(), [f.name for f in files], self.authorization)
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            out_path = str(Path(output_dir) / f"signed_cms_pkcs12_{int(time.time() * 1000)}.zip")
            with open(out_path, "wb") as out:
                out.write(zip_bytes)

            logger.info("CAdES PKCS12 signing complete. Output: %s", out_path)
            return out_path

        except requests.HTTPError as e:
            logger.error("SolidSign API error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error during CAdES PKCS12 signing: %s", e)
        finally:
            for fh in opened:
                fh.close()

        return None

    # ─── Form endpoint (all params from caller) ───────────────────────────────

    def sign_pkcs12_form(
        self,
        authorization: str,
        base_url: str,
        pfx_code: str,
        documents: List[Tuple[bytes, str]],
        profile: Optional[str] = None,
        hash_algorithm: Optional[str] = None,
        signature_packaging: Optional[str] = None,
        policy_version: Optional[str] = None,
    ) -> Optional[bytes]:
        """
        [EN]    Signs files via CAdES PKCS#12 with all parameters supplied by the caller.
        [PT-BR] Assina arquivos via CAdES PKCS#12 com todos os parâmetros fornecidos pelo chamador.
        """
        logger.info("CAdES PKCS12 form signing for %d file(s).", len(documents))
        sign_url = base_url.rstrip("/") + "/solidsign/dsig/cms/sign-pkcs12"
        headers = {"Authorization": authorization}

        req_files: dict = {}
        for i, (content, name) in enumerate(documents):
            req_files[f"document[{i}]"] = (name, content, "application/octet-stream")

        data: dict = {"pfxCode": pfx_code}
        if profile:               data["profile"] = profile
        if hash_algorithm:        data["hashAlgorithm"] = hash_algorithm
        if signature_packaging:   data["signaturePackaging"] = signature_packaging
        if policy_version:        data["policyVersion"] = policy_version

        try:
            resp = requests.post(sign_url, headers=headers, files=req_files, data=data, timeout=120)
            resp.raise_for_status()
            orig_names = [name for _, name in documents]
            return self._download_and_zip(resp.json(), orig_names, authorization)
        except requests.HTTPError as e:
            logger.error("SolidSign API error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error in CAdES PKCS12 form signing: %s", e)
        return None

    # ─── Internal helper ──────────────────────────────────────────────────────

    def _download_and_zip(self, sign_response: dict, original_names: List[str], auth: str) -> bytes:
        headers = {"Authorization": auth}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i, doc in enumerate(sign_response.get("documents", [])):
                links_obj = doc.get("_links") or {}
                download_url = (links_obj.get("self") or {}).get("href")
                if not download_url:
                    # [EN]    Fallback to legacy array format: "links": [{"rel","href"}]
                    # [PT-BR] Fallback para o formato antigo em array: "links": [{"rel","href"}]
                    download_url = next(
                        (lnk["href"] for lnk in doc.get("links", []) if lnk.get("rel") == "self"),
                        None,
                    )
                if not download_url:
                    continue
                r = requests.get(download_url, headers=headers, timeout=120)
                if r.status_code == 200:
                    zf.writestr(f"signed_{original_names[i]}", r.content)
        return buf.getvalue()
