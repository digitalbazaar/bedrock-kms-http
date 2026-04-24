# Bedrock Key Management System Testing

## Testing with proxy target enabled

To test in proxy mode, you must:

1. Install and start the proxy target in `tests/proxy-target`.
2. Run the tests with `TEST_PROXY=1`.

```
cd tests/proxy-target
npm i
cd ..
TEST_PROXY=1 npm t
```
