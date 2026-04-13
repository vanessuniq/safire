---
name: release-safire
description: Run the full Safire gem release workflow
argument-hint: Optional target version (e.g. 0.3.0); omit to auto-determine from CHANGELOG
---

# Safire Release Workflow

You are guiding the user through a complete Safire gem release. Follow each phase in order. **Never modify files or run commands without explicit user approval.** All commits must use `-s` (Signed-off-by) and one-line subjects.

## Context

Before proceeding, gather context by reading these files directly (do not shell out):
- Read `lib/safire/version.rb` to determine the current version
- Read `CHANGELOG.md` to find the `## [Unreleased]` section and its entries
- Run `git branch --show-current` to confirm the current branch
- Run `git status --short` to check for any uncommitted changes

---

## Phase 1: Determine Target Version

Target version argument: $ARGUMENTS

If `$ARGUMENTS` is blank, analyze the [Unreleased] CHANGELOG section and recommend a version bump:
- **PATCH** (X.Y.Z+1): bug fixes only
- **MINOR** (X.Y+1.0): new backward-compatible features
- **MAJOR** (X+1.0.0): breaking changes

Present your recommendation with reasoning. Ask the user to confirm or provide a different version before proceeding.

---

## Phase 2: Pre-Release Checks

Present this checklist and ask the user to approve running all checks before proceeding:

1. `bundle exec rspec` — all tests must pass
2. `bundle exec rubocop` — zero offenses
3. `bundle exec bundler-audit check --update` — no known vulnerabilities
4. `cd docs && bundle exec jekyll build` — docs must build clean

Run each check sequentially and report results. If any check fails, stop and clearly describe what needs to be fixed. Do not proceed to Phase 3 until all checks pass.

---

## Phase 3: Create Release Branch

Ask the user to approve creating the release branch, then run:

```
git checkout main
git pull origin main
git checkout -b release-X.Y.Z
```

Replace `X.Y.Z` with the confirmed target version.

---

## Phase 4: Update CHANGELOG.md (docs commit)

Show the user the exact diff you will make:
- Rename `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` (use today's date)
- Add a fresh empty `## [Unreleased]` section above the new versioned entry

Wait for approval, then edit `CHANGELOG.md`.

After editing, ask the user to approve this commit:
```
git add CHANGELOG.md
git commit -s -m "Update CHANGELOG for vX.Y.Z"
```

Stage `CHANGELOG.md` only — no other files.

---

## Phase 5: Bump Version and Update Gemfile.lock (release commit)

Show the user the exact change to `lib/safire/version.rb`:
```ruby
VERSION = 'X.Y.Z'.freeze
```

Wait for approval, then edit the file and run `bundle install` to regenerate `Gemfile.lock`.

Ask the user to approve this commit:
```
git add lib/safire/version.rb Gemfile.lock
git commit -s -m "Bump version to X.Y.Z"
```

Stage `lib/safire/version.rb` and `Gemfile.lock` only — no other files.

---

## Phase 6: Local Gem Verification

Ask the user to approve running local verification (no files will be committed):

```bash
gem build safire.gemspec
gem install ./safire-X.Y.Z.gem
ruby -e "require 'safire'; puts Safire::VERSION"
rm safire-X.Y.Z.gem
```

The `ruby -e` line must print `X.Y.Z`. If it does not, stop and report the issue. Never commit the `.gem` file.

---

## Phase 7: Push Release Branch

Ask the user to approve:
```
git push -u origin release-X.Y.Z
```

---

## Phase 8: Open Release PR

Show the proposed PR and ask for approval before running `gh pr create`:

- **Title:** `Release vX.Y.Z`
- **Body:** the full CHANGELOG entry for this version (the `## [X.Y.Z] - YYYY-MM-DD` block)

---

## Phase 9: Post-Merge Instructions

After the PR is created, tell the user the remaining manual steps:

1. **Merge the PR** once CI passes and it is approved.
2. **Create a GitHub Release** after merge:
   - Tag: `vX.Y.Z` on `main`
   - Title: `Safire vX.Y.Z`
   - Notes: the CHANGELOG entry for this version
3. **Publishing is automated** — `.github/workflows/publish-gem.yml` triggers on release creation.
4. **Verify** once published: `gem info safire -r`

---

## Rules (never violate)

- All commits use `-s`; subjects are one-line only
- Two-commit structure on the release branch: docs commit (CHANGELOG) then release commit (version.rb + Gemfile.lock)
- Never commit a `.gem` file
- Separate doc changes from code changes into distinct commits
- Always get explicit user approval before modifying files or running commands
