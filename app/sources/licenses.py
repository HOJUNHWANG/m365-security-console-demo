from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get("/subscribedSkus")
    items = []
    for s in data.get("value", []):
        consumed = s.get("consumedUnits", 0)
        total = (s.get("prepaidUnits", {}) or {}).get("enabled", 0)
        if total == 0 and consumed == 0:
            continue
        if total >= 10000:
            continue
        items.append({"sku": s.get("skuPartNumber"), "consumed": consumed, "total": total})
    items.sort(key=lambda i: i["consumed"], reverse=True)
    return {"available": True, "skus": items[:15]}
