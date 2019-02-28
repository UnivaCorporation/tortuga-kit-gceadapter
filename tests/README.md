These tests must be run on a live system as there are no mocks currently
available for GCE.

On a Tortuga installation, run the following as `root`:

```shell
pip install pytest
pytest -sv tests
```

Where `tests` contains the `tests` subdirectory from the source repository.
