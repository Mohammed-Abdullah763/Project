"""
app/routers/files.py
────────────────────
File upload and management endpoints.

POST   /files/upload           — upload + extract text
GET    /files/                 — list user's files
GET    /files/{file_id}        — get file metadata + extracted text
POST   /files/{file_id}/summarise  — AI-summarise the file
DELETE /files/{file_id}        — delete file
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.file import UploadedFile
from app.models.user import User
from app.services.file_service import (
    delete_file, extract_text_from_file, get_file_info, save_upload
)
from app.services import ai_service

router = APIRouter(prefix="/files", tags=["Files"])


@router.post("/upload", status_code=201)
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    meta = await save_upload(file, current_user.id)
    text = extract_text_from_file(meta["saved_path"])

    db_file = UploadedFile(
        user_id=current_user.id,
        file_id=meta["file_id"],
        original_name=meta["original_name"],
        saved_path=meta["saved_path"],
        extension=meta["extension"],
        size_bytes=meta["size_bytes"],
        extracted_text=text[:50000],   # cap at 50K chars in DB
    )
    db.add(db_file)
    await db.flush()

    return {
        "file_id": meta["file_id"],
        "id": db_file.id,
        "name": meta["original_name"],
        "size_bytes": meta["size_bytes"],
        "word_count": len(text.split()),
        "preview": text[:500],
    }


@router.get("/")
async def list_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(UploadedFile)
        .where(UploadedFile.user_id == current_user.id)
        .order_by(UploadedFile.uploaded_at.desc())
    )
    files = res.scalars().all()
    return [
        {
            "id": f.id,
            "file_id": f.file_id,
            "name": f.original_name,
            "extension": f.extension,
            "size_bytes": f.size_bytes,
            "has_summary": bool(f.summary),
            "uploaded_at": f.uploaded_at.isoformat(),
        }
        for f in files
    ]


@router.get("/{file_id}")
async def get_file(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(UploadedFile).where(
            UploadedFile.file_id == file_id,
            UploadedFile.user_id == current_user.id,
        )
    )
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    return {
        "id": f.id,
        "file_id": f.file_id,
        "name": f.original_name,
        "extension": f.extension,
        "extracted_text": f.extracted_text,
        "summary": f.summary,
        "uploaded_at": f.uploaded_at.isoformat(),
    }


@router.post("/{file_id}/summarise")
async def summarise_file(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(UploadedFile).where(
            UploadedFile.file_id == file_id,
            UploadedFile.user_id == current_user.id,
        )
    )
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    result = ai_service.summarise(f.extracted_text, "detailed")
    f.summary = result["summary"]
    current_user.total_ai_calls += 1

    return {"file_id": file_id, "summary": result["summary"]}


@router.delete("/{file_id}")
async def delete_file_endpoint(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(UploadedFile).where(
            UploadedFile.file_id == file_id,
            UploadedFile.user_id == current_user.id,
        )
    )
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    delete_file(f.saved_path)
    await db.delete(f)
    return {"message": "File deleted."}
