"""Vault backend: the Bitwarden CLI's `bw serve` local REST API.

Any object with sync(), collection_id() and items(collection_id) can stand in
for BwServe (the tests use a fake).
"""
import re

import httpx

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class BwServe:
    def __init__(self, url, collection):
        self.http = httpx.Client(base_url=url, timeout=30)
        self.collection = collection
        self._cid = None

    def _get(self, path, **params):
        r = self.http.get(path, params=params)
        body = r.json()  # {"success": bool, "message": str, "data": {"object": "list", "data": [...]}}
        if not body.get("success"):
            raise RuntimeError(f"bw serve {path} failed: {body.get('message') or r.status_code}")
        return body["data"]

    def sync(self):
        self.http.post("/sync").raise_for_status()

    def collection_id(self):
        if not self._cid:
            if GUID.match(self.collection):
                self._cid = self.collection
            else:
                found = [c["id"] for c in self._get("/list/object/collections", search=self.collection)["data"]
                         if c.get("name") == self.collection]
                if len(found) != 1:
                    raise RuntimeError(f"collection {self.collection!r} matched {len(found)} collections; "
                                       "set VALET_COLLECTION to the collection id")
                self._cid = found[0]
        return self._cid

    def items(self, collection_id):
        return self._get("/list/object/items", collectionid=collection_id)["data"]
