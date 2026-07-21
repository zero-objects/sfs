# GitHub Actions — Matrix Strategy

Source: https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs

## Key facts used in `.github/workflows/ci.yml`

### Defining a matrix

```yaml
jobs:
  test:
    strategy:
      fail-fast: false        # do NOT cancel other jobs when one fails
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable]
    runs-on: ${{ matrix.os }}
```

With 3 OS values × 1 Rust version = **3 parallel jobs**.

### Accessing matrix values in steps

Use `${{ matrix.variable_name }}` in any field:

```yaml
- uses: dtolnay/rust-toolchain@master
  with:
    toolchain: ${{ matrix.rust }}
```

### `fail-fast`

- `true` (default): cancels all remaining jobs as soon as one fails.
- `false`: lets all jobs complete even if one fails — preferred for a
  cross-platform matrix so a Windows failure doesn't hide a macOS failure.

### `include` / `exclude`

Not used here but available to add one-off extra combinations or remove
specific OS×toolchain pairs.

### Cache key pattern used

```
${{ runner.os }}-cargo-${{ matrix.rust }}-${{ hashFiles('**/Cargo.lock') }}
```

`runner.os` is injected automatically (`Linux`, `macOS`, `Windows`).
