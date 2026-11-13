# Synthetic Rails verification fixtures

This disposable Rails application contains original synthetic accounts and notes for Mergable verification experiments. It contains no customer code, credentials, personal records, or Mergable product implementation. It is intended for a public test repository owned by a free GitHub organization.

The public interface selects an account by a route parameter and reads one of its notes. This deliberately simple selection is a test fixture, not an authentication system or a production application. The behavior under test is that an account-scoped lookup returns its own note, while another account's note and a missing note receive the same not-found response.

## Note response

`GET /accounts/:account_id/notes/:id` returns HTTP 200 with `{"title":"<note title>"}` when the note belongs to the selected account. A note owned by another account or a missing note returns HTTP 404 with `{"error":"not_found"}`.

The [Minitest request examples](test/integration/note_access_test.rb) and [RSpec request examples](spec/requests/note_access_spec.rb) cover these responses.

## Run the checked-in examples

Use Ruby 3.4.5. Install dependencies and create the disposable SQLite database:

```sh
bundle install
RAILS_ENV=test bundle exec rails db:prepare
bundle exec rails test
bundle exec rspec
```

Minitest covers model/domain and request/integration behavior with four tests and eight assertions. RSpec Rails covers equivalent behavior with five examples. All test data is created inside transactional tests. The lockfile includes the Linux platform used by CI.

Rails is pinned to 8.0.2.1 and RSpec Rails to the supported 8.0 series. Minitest is constrained to major version 5 because the Rails 8.0 test runner is incompatible with Minitest 6's runner interface. These versions are a fixture compatibility matrix, not a promise of support for every Rails or Ruby release.

## Configure native-queue validation

After independently inspecting and publishing this repository, keep `main` as its default branch. The checked-in workflow runs on pull requests, main pushes, manual requests, and native `merge_group` checks. Each matrix job prepares its own ephemeral test database.

The required checks for the protected default branch are exactly:

- `Rails fixtures (minitest)`.
- `Rails fixtures (rspec)`.

Install a merge-queue rule on the protected branch and require both checks. Wait for the first actual workflow execution before treating either check as available or passing. PR-head results alone cannot establish that the native queue's integration candidate was tested. The workflow's check on a merge-group event applies to that group's actual checkout.

The baseline workflow uses only read access to repository contents, disables persisted checkout credentials, and references immutable action commit IDs. It consumes no repository secrets. It executes only the checked-in fixture tests and does not accept source code or test code as dispatch input.

## Scope of this fixture

This is ordinary baseline CI on GitHub-hosted runners. It does not establish a restricted execution contract for generated code. Fresh runners, read-only permissions, and disabled checkout credentials do not themselves prove runtime isolation. No generated-code capability, provider key, automatic merge authority, production deployment, or Mergable integration is enabled by these files.

Local checks detected a deliberately introduced unscoped lookup: both frameworks reported a cross-account read returning 200 instead of 404 and a model lookup failing to raise not-found. The correct scoped lookup was restored, and both complete suites passed afterward. This small regression probe is not a mutation score, production reliability study, or formal proof.

Provider references:

- [RSpec Rails supported versions](https://github.com/rspec/rspec-rails).
- [GitHub merge-group event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group).
- [GitHub merge-queue setup](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).
- [Official checkout action](https://github.com/actions/checkout).
- [Official Ruby setup action](https://github.com/ruby/setup-ruby).
