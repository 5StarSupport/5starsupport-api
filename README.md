# 5 Star Support API (Netlify Functions)

## Deploy (Drag & Drop)
1) Zip the contents of this folder (so the zip root contains netlify/, netlify.toml, package.json)
2) Netlify dashboard -> Add new site -> Deploy manually -> drop the zip
3) In Netlify -> Site settings -> Environment variables, add:
   - WEBSITE_API_KEY
   - CRM_API_KEY (optional but recommended)
   - CRM_USERNAME
   - CRM_PASSWORD_HASH (bcrypt hash)
   - JWT_SECRET

## Endpoints
Base path (Netlify): /.netlify/functions

- POST  /leads                 (Website or CRM) create a lead
- GET   /leads                 (CRM) list leads
- GET   /leads/<id>            (CRM) get lead
- PATCH /leads/<id>            (CRM) update lead
- PATCH /leads/<id>/status     (CRM) update status
- POST  /leads/<id>/notes      (CRM) add note
- DELETE /leads/<id>           (CRM) delete lead

Auth:
- Website: Authorization: Bearer <WEBSITE_API_KEY>
- CRM:     Authorization: Bearer <CRM_API_KEY>  OR  login for JWT

Login:
- POST /auth-login with { "username": "...", "password": "..." }
