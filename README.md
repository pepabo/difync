# Difync

Difync is a command-line tool for synchronizing [Dify.AI](https://dify.ai) workflow DSLs (YAML) between your local filesystem and Dify's API. It allows you to version control your Dify workflows using Git while keeping them in sync with the Dify platform.

## Features

- Bidirectional synchronization based on modification time
- Force upload or download direction
- Dry run mode for testing without making changes
- Support for multiple Dify applications
- Detailed logging and statistics
- Environment variables via `.env` file
- Internationalization support for filenames (including Japanese characters)
- Automatic filename deduplication for apps with identical names

## Installation

```bash
# Clone the repository
git clone https://github.com/pepabo/difync.git
cd difync

# Copy the sample .env file and edit it with your credentials
cp .env.sample .env
# Edit the .env file with your Dify API credentials
vim .env

# Build the binary
go build -o difync ./cmd/difync
```

## Usage

```bash
# Initialize app map and download DSL files
./difync init

# Basic usage (using credentials from .env file)
./difync

# Override base URL from command line
./difync --base-url https://dify.example.com

# Force upload local DSL files to Dify
./difync --force upload

# Force download DSL files from Dify to local
./difync --force download

# Perform a dry run without making any changes
./difync --dry-run

# Specify a custom DSL directory and app map file
./difync --dsl-dir custom/dsl --app-map custom/app_map.json
```

## Configuration

### Environment Variables

Difync reads configuration from a `.env` file in the project root:

```
# Dify API Configuration
DIFY_BASE_URL=https://cloud.dify.ai
DIFY_EMAIL=your_email_here
DIFY_PASSWORD=your_password_here

# Optional Configuration
# DSL_DIRECTORY=custom/dsl
# APP_MAP_FILE=custom/app_map.json
```

### App Mapping

Difync requires an app mapping file (`app_map.json` by default) that maps local DSL filenames to Dify application IDs:

```json
{
  "apps": [
    {
      "filename": "my-chatbot.yaml",
      "app_id": "app-xxxxxxxxxxxxxxxx"
    },
    {
      "filename": "my-assistant.yaml",
      "app_id": "app-yyyyyyyyyyyyyyyy"
    }
  ]
}
```

You can automatically generate this file by running `./difync init`, which will download all available apps and create the mapping file.

The DSL files should be placed in the DSL directory (`dsl/` by default).

## How It Works

Difync synchronizes files based on modification time:

1. It checks the local DSL file's modification time
2. It fetches the Dify application's last update time
3. It compares the two timestamps:
   - If the local file is newer, it uploads to Dify
   - If the Dify app is newer, it downloads to local
   - If they're the same, it does nothing

## Command-Line Options

```
Commands:
  init             Initialize app map and download all DSL files

Options:
  --base-url string   Dify API base URL (overrides env: DIFY_BASE_URL)
  --dsl-dir string    Directory containing DSL files (default "dsl")
  --app-map string    Path to app mapping file (default "app_map.json")
  --dry-run           Perform a dry run without making any changes
  --force string      Force sync direction: 'upload', 'download', or empty for bidirectional
  --verbose           Enable verbose output
```

Note: Email and password must be set in environment variables (DIFY_EMAIL and DIFY_PASSWORD).

## Development

### Testing

Run the tests:

```bash
go test ./...
```

Generate test coverage report:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

Current test coverage: ~78%

## License

This project is licensed under the MIT License - see the LICENSE file for details. 