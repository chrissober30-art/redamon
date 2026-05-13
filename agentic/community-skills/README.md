# Community Skills

Ready-to-use attack skill workflows contributed by the community. Download any `.md` file and upload it via **Global Settings > Agent Skills** to activate it for your user.

## Skills

| Skill | Author | Description |
|-------|--------|-------------|
| [api_testing.md](api_testing.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | JWT exploitation, GraphQL attacks, REST API vulns, 403 bypass |
| [xss_exploitation.md](xss_exploitation.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Reflected, stored, DOM-based XSS with WAF bypass techniques |
| [sqli_exploitation.md](sqli_exploitation.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Advanced SQL injection beyond sqlmap basics |
| [xxe.md](xxe.md) | [@samugit83](https://github.com/samugit83) | XML External Entity: file disclosure, SSRF, OOB DTD, XInclude, XSLT, SVG/OOXML uploads |
| [bfla_exploitation.md](bfla_exploitation.md) | [@samugit83](https://github.com/samugit83) | Broken Function Level Authorization: vertical privilege escalation, transport drift, gateway header trust, job replay |
| [insecure_deserialization.md](insecure_deserialization.md) | [@samugit83](https://github.com/samugit83) | Java/PHP/Python/.NET/Ruby gadget chains via ysoserial, phpggc, pickle, BinaryFormatter, Marshal |
| [idor_bola_exploitation.md](idor_bola_exploitation.md) | [@samugit83](https://github.com/samugit83) | Object-level authz (IDOR, BOLA, cross-tenant) with two-identity swap across REST/GraphQL/batch/job/storage |
| [mass_assignment.md](mass_assignment.md) | [@samugit83](https://github.com/samugit83) | Privileged-field injection, ownership takeover, feature-gate and billing tampering across REST, GraphQL, JSON Patch, batch writes |
| [subdomain_takeover.md](subdomain_takeover.md) | [@samugit83](https://github.com/samugit83) | Dangling CNAME / orphaned NS / unverified provider claim across S3, GitHub Pages, Heroku, Azure, CloudFront, Fastly and ~80 more |
| [insecure_file_uploads.md](insecure_file_uploads.md) | [@samugit83](https://github.com/samugit83) | Web shells, SVG/HTML stored XSS, magic-byte and config-drop bypass, ImageMagick/Ghostscript/ExifTool abuse, zip slip, presigned-URL tampering, processing-race AV bypass |

## Contributing

1. Create your `.md` skill file following the [Writing a Skill File](https://github.com/samugit83/redamon/wiki/Agent-Skills#writing-a-skill-file) format
2. Test it in your RedAmon instance by uploading via Global Settings
3. Fork the repo, add your `.md` file to this folder, and update this table with your GitHub username
4. Open a Pull Request
