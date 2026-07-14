"""
[EN]    CAdES (CMS) signing example using a PKCS#12 certificate pre-imported into SolidSign cache.
        Start: uvicorn main:app --port 8091 --reload
        Batch: POST http://localhost:8091/api/cms/sign-pkcs12
        Form:  POST http://localhost:8091/api/cms/sign/form

[PT-BR] Exemplo de assinatura CAdES (CMS) com certificado PKCS#12 pré-importado na cache do SolidSign.
        Iniciar: uvicorn main:app --port 8091 --reload
        Lote:    POST http://localhost:8091/api/cms/sign-pkcs12
        Form:    POST http://localhost:8091/api/cms/sign/form
"""

import logging
import os
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import Response

from service import CmsPkcs12Service

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")

app = FastAPI(title="SolidSign — CMS PKCS12 Example")
service = CmsPkcs12Service()


@app.post("/api/cms/sign-pkcs12")
async def sign_pkcs12_folder():
    """
    [EN]    Scans the configured input folder for files and signs them in batch via CAdES.
    [PT-BR] Escaneia a pasta de entrada configurada por arquivos e os assina em lote via CAdES.
    """
    input_path = os.getenv("SOLIDSIGN_BATCH_INPUT_PATH", "")
    output_path = os.getenv("SOLIDSIGN_BATCH_OUTPUT_PATH", "")
    cert_id = os.getenv("SOLIDSIGN_CERT_ID", "")

    folder = Path(input_path)
    if not folder.exists() or not folder.is_dir():
        return {"error": f"Invalid input path: {input_path}"}

    all_files = [f for f in folder.iterdir() if f.is_file()]
    if not all_files:
        return {"message": f"No files found in {input_path}"}

    result_path = service.sign_pkcs12(all_files, cert_id, output_path)
    if result_path:
        return {"message": f"Processing completed! ZIP generated at: {result_path}"}
    return {"error": "Processing failed. Check logs."}


@app.post("/api/cms/sign/form")
async def sign_form(
    document: List[UploadFile] = File(...),
    authorization: str = Form(...),
    baseUrl: str = Form(...),
    pfxCode: str = Form(...),
    profile: Optional[str] = Form(default=None),
    hashAlgorithm: Optional[str] = Form(default=None),
    signaturePackaging: Optional[str] = Form(default=None),
    policyVersion: Optional[str] = Form(default=None),
):
    """
    [EN]    Form signing endpoint — receives documents and all parameters from the request.
    [PT-BR] Endpoint de formulário — recebe documentos e todos os parâmetros da requisição.
    """
    docs = [(await d.read(), d.filename) for d in document]

    zip_bytes = service.sign_pkcs12_form(
        authorization=authorization,
        base_url=baseUrl,
        pfx_code=pfxCode,
        documents=docs,
        profile=profile,
        hash_algorithm=hashAlgorithm,
        signature_packaging=signaturePackaging,
        policy_version=policyVersion,
    )

    if zip_bytes:
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=signed_cms.zip"},
        )
    return Response(content="Processing failed. Check logs.", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8091)
