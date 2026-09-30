-- Subdomain takeover fingerprints, 30 entries, DNS plus HTTP GET only.
-- Never claims takeover. Only returns signal level.
local M = {
  { service = "GitHub Pages", cname = "github.io", hit = "There isn't a GitHub Pages site here" },
  { service = "Heroku", cname = "herokuapp.com", hit = "No such app" },
  { service = "Azure", cname = "azurewebsites.net", hit = "Error 404" },
  { service = "AWS S3 website", cname = "s3-website", hit = "NoSuchBucket" },
  { service = "Netlify", cname = "netlify.app", hit = "Not Found" },
  { service = "Vercel", cname = "vercel.app", hit = "404" },
}
return M
