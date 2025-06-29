# SIA-Scout

**SIA-Scout** is a Python-based tool designed to perform large-scale threat intelligence gathering from the Spamhaus Intelligence API (SIA). It has evolved from a simple script into a robust, asynchronous data pipeline that leverages a local SQLite database for persistent storage and analysis.

The primary goal of this tool is to scan a large list of IP network blocks (CIDRs), collect all associated threat listings from Spamhaus, and provide a foundation for analyzing and visualizing the threat landscape of a specific region or country.

## Key Features

-   **High-Performance Collection:** Utilizes `asyncio` and `aiohttp` to run dozens of concurrent API requests, dramatically speeding up data collection.
-   **Robust Database Storage:** Replaces fragile flat-file storage with a resilient **SQLite** database, preventing data duplication and enabling complex queries.
-   **Live & Historical Data:** Capable of collecting both the current "live" threat data and historical data over a specified period (e.g., the last year).
-   **Intelligent Caching:** The "live" collection mode is idempotent; it tracks already-scanned CIDRs and will automatically skip them on subsequent runs, saving API quota and time.
-   **Automatic CIDR Splitting:** Automatically breaks down large network blocks (e.g., `/16`, `/22`) into API-compliant `/24` chunks for scanning.
-   **Modular Architecture:** The code is logically separated into modules for the API client, data collector, analyzer, and visualizer, making it easy to maintain and extend.
-   **Command-Line Interface:** A clear and simple CLI for running different actions like collecting, analyzing, or visualizing data.
-   **Data Analysis & Visualization:** Built-in modules to generate summary text reports and graphical charts (`.png` files) from the collected data.

## Architecture

The project is structured into a main application and a Python package named `sia_scout`.

```
sia_scout/
├── .env                  # <-- Your secret credentials (must be created)
├── config.py             # All application settings and configurations
├── main.py               # The main entry point and CLI handler
├── requirements.txt      # Project dependencies
│
├── sia_scout/
│   ├── __init__.py
│   ├── client.py         # Manages all async communication with the Spamhaus API
│   ├── collector.py      # Orchestrates the data collection process (live & history)
│   ├── database.py       # Handles database creation and all data insertion
│   ├── analyzer.py       # Reads from the DB and generates text-based reports
│   └── visualizer.py     # Reads from the DB and generates graphical charts
│
└── targets/
    └── cidrs.txt         # <-- A list of CIDRs to scan (one per line)
```

## Setup Instructions

Follow these steps to get SIA-Scout running on your machine.

**1. Prerequisites**
- Python 3.10+
- `git`

**2. Clone the Repository**
```bash
git clone <your-repository-url>
cd sia_scout
```

**3. Set Up a Virtual Environment**
It is highly recommended to use a virtual environment.
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
```

**4. Install Dependencies**
```bash
pip install -r requirements.txt
```

**5. Configure Credentials**
Create a `.env` file in the root of the project directory. You can copy the example: `cp .env.example .env` (if you create an example file).

Fill it with your Spamhaus Intelligence API credentials:
```
# .env
SIA_USERNAME="your_email@example.com"
SIA_PASSWORD="your_sia_password"
```

**6. Define Your Targets**
Create the `targets` directory if it doesn't exist. Inside it, create a file named `cidrs.txt` and add the network blocks you want to scan, one per line.
```
# targets/cidrs.txt
41.96.0.0/19
102.64.0.0/16
# Add any other CIDRs here...
```

## Usage

SIA-Scout is operated via the command line. The main actions are `collect`, `collect-history`, `analyze`, `visualize`, and their history-focused variants.

### Data Collection

**To run a fresh scan for LIVE data (uses caching):**
```bash
python main.py collect
```

**To run a scan for HISTORICAL data:**
The default lookback period is 364 days.
```bash
python main.py collect-history
```
You can specify a custom number of days with the `--days` flag:
```bash
python main.py collect-history --days 30
```

### Data Analysis & Visualization

**To generate a text report from LIVE data:**
```bash
python main.py analyze
```

**To generate a text report from HISTORICAL data:**
```bash
python main.py analyze-history
```

**To generate graph images from LIVE data:**
```bash
python main.py visualize
```

**To generate a trend graph from HISTORICAL data:**
```bash
python main.py visualize-history
```

## Output

All generated files are placed in the `output/` directory:
-   `sia_scout.db`: The SQLite database containing all collected data in `hits` and `history_hits` tables.
-   `sia_scout.log`: A detailed log of the application's activity for debugging.
-   `token.json`: The cached authentication token to speed up subsequent runs.
-   `top_heuristics.png`: A bar chart of the most common detection heuristics.
-   `threat_composition.png`: A donut chart showing the proportion of threats by dataset.
-   `historical_threats_over_time.png`: (Generated by `visualize-history`) A line chart showing daily threat trends.

## Daily Workflow Example

1.  **Start Fresh (Optional):** If you want a completely new "live" scan every day, you can clear the database cache.
    ```bash
    rm output/sia_scout.db
    ```
2.  **Collect Today's Live Data:** The tool will scan all CIDRs as the cache is now empty.
    ```bash
    python main.py collect
    ```
3.  **Analyze and Visualize:**
    ```bash
    python main.py analyze
    python main.py visualize
    ```

## Future Roadmap

-   **Implement Pagination:** Add logic to handle CIDRs with more than 2000 listings to ensure 100% data completeness.
-   **WHOIS Enrichment:** Add an `organization` field to the database by performing WHOIS lookups on CIDRs for better contextual analysis.
-   **Domain/URL Scanning:** Extend the collector to use the `DOMAIN` dataset available via the API.
-   **Web Dashboard:** Create an interactive dashboard (e.g., with Streamlit or Dash) to explore the data visually.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.