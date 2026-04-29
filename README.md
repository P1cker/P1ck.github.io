# 0xdead.p1ck.space

Vulnerability analysis and exploitation research blog.

## Local Development

```bash
# Install dependencies (first time only)
bundle install

# Preview with drafts
bundle exec jekyll serve --drafts

# Preview published posts only
bundle exec jekyll serve
```

Site loads at `http://localhost:4000`.

## Publishing Workflow

```
_drafts/xxx.md          → work in progress, not published
        ↓ review + add screenshots
_posts/YYYY-MM-DD-xxx   → published on push
```

1. Write draft in `_drafts/`
2. Add screenshots to `assets/images/<post-slug>/`
3. Preview locally with `--drafts`
4. Review content, verify no sensitive info (IPs, credentials, internal hostnames)
5. Move to `_posts/` with date prefix
6. `git add _posts/ assets/images/ && git push`

## Directory Structure

```
_config.yml          Site config (title, URL, permalink)
_layouts/            HTML templates (default, post)
_includes/           Reusable HTML fragments (header, footer)
_sass/main.scss      Dark theme styles
assets/css/          Entry point SCSS
assets/images/       Post screenshots and diagrams
_posts/              Published articles
_drafts/             Work-in-progress articles
```

## Security Notes

- **Never push** screenshots containing real IPs, credentials, or internal hostnames
- **Scrub** any sensitive data from screenshots before committing
- Drafts in `_drafts/` are tracked by git — review before push
- `_site/` and `.jekyll-cache/` are excluded via `.gitignore`

## Deployment

GitHub Pages auto-deploys from `main` branch. Push to main = publish.

Custom domain: `0xdead.p1ck.space` (CNAME → `p1cker.github.io`)
