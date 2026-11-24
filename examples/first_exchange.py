import os
from remit import Remit, t

client = Remit.from_env()
finance = client.holder(os.environ.get("HOLDER", "http://127.0.0.1:8444"))
answer = finance.query(
    "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region ORDER BY region",
    returns=t.list(t.struct(
        region=t.enum(*finance.enums("crm.accounts.region")),
        arr=t.float(min=0, max=1e10, precision=1000),
    ), max=4),
    purpose="analytics",
)

print(answer.value)
print("receipt verified:", answer.receipt.verify())
print("labels:", answer.labels)
print("terms:", answer.terms)
