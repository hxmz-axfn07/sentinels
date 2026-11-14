from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings

MULTIPART_OVERHEAD_BYTES = 64 * 1024


class UploadRequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] != "/api/v1/analyses/upload"
        ):
            await self.app(scope, receive, send)
            return

        request_limit = settings.max_upload_size_bytes + MULTIPART_OVERHEAD_BYTES
        content_length = next(
            (
                value
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ),
            None,
        )
        if content_length is not None and content_length.isdigit():
            if int(content_length) > request_limit:
                await _send_too_large(send)
                return

        received_bytes = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received_bytes, too_large
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > request_limit:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        async def limited_send(message: Message) -> None:
            if not too_large:
                await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            if not too_large:
                raise
        if too_large:
            await _send_too_large(send)


async def _send_too_large(send: Send) -> None:
    body = (
        b'{"detail":{"code":"upload_too_large",'
        b'"message":"The upload request exceeds the configured limit."}}'
    )
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
