"""Licence usage - consumed versus owned units per SKU (spot over-assignment and spare seats)."""
from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get("/subscribedSkus")
    items = []
    for s in data.get("value", []):
        consumed = s.get("consumedUnits", 0)
        total = (s.get("prepaidUnits", {}) or {}).get("enabled", 0)
        # Drop noise: SKUs we do not own (0/0) and free/unlimited SKUs (FLOW_FREE,
        # POWER_BI_STANDARD, POWERAPPS_DEV and similar, whose total is a sentinel like
        # 10000 or 1000000). Neither is meaningful for licence management - keep only
        # paid, assigned SKUs.
        if total == 0 and consumed == 0:
            continue
        if total >= 10000:
            continue
        items.append({"sku": s.get("skuPartNumber"), "consumed": consumed, "total": total})
    items.sort(key=lambda i: i["consumed"], reverse=True)
    return {"available": True, "skus": items[:15]}
