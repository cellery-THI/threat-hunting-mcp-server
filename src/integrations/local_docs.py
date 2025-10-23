import asyncio
from typing import List, Dict, Optional
import logging
from datetime import datetime
import json
import os
from ..models.hunt import ThreatHunt

logger = logging.getLogger(__name__)

class LocalDocsThreatIntel:
    """Manages threat hunting documentation and tracking using the local filesystem"""

    def __init__(self, root_path: str):
        self.root_path = root_path
        self.playbooks_path = os.path.join(self.root_path, "docs/playbooks")
        self.threat_intel_path = os.path.join(self.root_path, "docs/threat_intelligence")
        self.detections_path = os.path.join(self.root_path, "docs/detections")
        self.tickets_log_path = os.path.join(self.root_path, "hunt_tickets.log")

    async def get_hunting_playbooks(self, space: str = "THREATHUNT") -> List[Dict]:
        """Retrieves threat hunting playbooks from the local filesystem"""
        playbooks = []
        for root, _, files in os.walk(self.playbooks_path):
            for file in files:
                if file.endswith(".md"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        content = f.read()
                    playbooks.append({
                        "id": file,
                        "title": file.replace(".md", ""),
                        "content": content,
                        "techniques": [],  # Placeholder
                        "queries": [],  # Placeholder
                        "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    })
        logger.info(f"Retrieved {len(playbooks)} hunting playbooks from {self.playbooks_path}")
        return playbooks

    async def create_hunt_ticket(self, hunt: ThreatHunt, project_key: str = "HUNT") -> Optional[str]:
        """Logs a hunt ticket to a local file"""
        try:
            ticket_id = f"{project_key}-{hunt.hunt_id}"
            issue_dict = {
                "ticket_id": ticket_id,
                "summary": f"Threat Hunt: {hunt.hypothesis[:100]}...",
                "description": self._format_hunt_description(hunt),
                "status": "OPEN",
                "created_at": datetime.utcnow().isoformat(),
            }
            with open(self.tickets_log_path, "a") as f:
                f.write(json.dumps(issue_dict) + "\n")
            logger.info(f"Created hunt ticket {ticket_id} for hunt {hunt.hunt_id}")
            return ticket_id
        except Exception as e:
            logger.error(f"Error creating hunt ticket: {str(e)}")
            return None

    async def update_hunt_ticket(self, ticket_key: str, hunt: ThreatHunt) -> bool:
        """Updates a hunt ticket in the local log"""
        # This is a simplified implementation. A real implementation would
        # need to find and update the specific ticket in the log file.
        # For now, we'll just add a new entry indicating an update.
        try:
            update_dict = {
                "ticket_id": ticket_key,
                "status": "UPDATED",
                "updated_at": datetime.utcnow().isoformat(),
                "description": self._format_hunt_description(hunt),
            }
            if hunt.results:
                comment = self._format_hunt_results_comment(hunt.results)
                update_dict["comment"] = comment

            with open(self.tickets_log_path, "a") as f:
                f.write(json.dumps(update_dict) + "\n")
            logger.info(f"Updated hunt ticket {ticket_key}")
            return True
        except Exception as e:
            logger.error(f"Error updating hunt ticket: {str(e)}")
            return False

    async def create_detection_page(self, detection: Dict, space: str = "THREATHUNT") -> Optional[str]:
        """Creates a markdown file for a new detection rule"""
        try:
            page_title = f"Detection: {detection['name']}"
            page_content = self._format_detection_page_content(detection)
            file_name = f"{detection['name'].replace(' ', '_')}.md"
            file_path = os.path.join(self.detections_path, file_name)
            with open(file_path, "w") as f:
                f.write(page_content)
            logger.info(f"Created detection page: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error creating detection page: {str(e)}")
            return None

    async def get_threat_intelligence(self, space: str = "THREATINTEL") -> List[Dict]:
        """Retrieves threat intelligence from the local filesystem"""
        threat_intel = []
        for root, _, files in os.walk(self.threat_intel_path):
            for file in files:
                if file.endswith(".md"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        content = f.read()
                    threat_intel.append({
                        "id": file,
                        "title": file.replace(".md", ""),
                        "content": content,
                        "iocs": {},  # Placeholder
                        "techniques": [],  # Placeholder
                        "actors": [],  # Placeholder
                    })
        logger.info(f"Retrieved {len(threat_intel)} threat intelligence documents from {self.threat_intel_path}")
        return threat_intel

    def _format_hunt_description(self, hunt: ThreatHunt) -> str:
        """Formats hunt information for the ticket description"""
        return f"""
## Threat Hunt Details

**Hunt ID:** {hunt.hunt_id}
**Type:** {hunt.hunt_type.value}
**Phase:** {hunt.phase}
**Maturity Level:** HMM{hunt.maturity_level.value}
**Created:** {hunt.created_at.isoformat() if hunt.created_at else 'Unknown'}

## Hypothesis
{hunt.hypothesis}

## Data Sources
{chr(10).join(f"* {source}" for source in hunt.data_sources)}

## Queries
{chr(10).join(f"```\n{query}\n```" for query in hunt.queries)}

## Results
{self._format_results_summary(hunt.results) if hunt.results else 'Hunt in progress...'}
"""

    def _format_results_summary(self, results: Dict) -> str:
        """Formats hunt results for display"""
        if not results:
            return "No results available"
        return f"""
**Success:** {'Yes' if results.get('success') else 'No'}
**Confidence:** {results.get('confidence', 0):.2f}
**Findings:** {len(results.get('findings', []))}
**Recommendations:** {len(results.get('recommendations', []))}
"""

    def _format_hunt_results_comment(self, results: Dict) -> str:
        """Formats hunt results as a comment"""
        return f"""
Hunt execution completed with the following results:

**Success:** {'✅ Yes' if results.get('success') else '❌ No'}
**Confidence Score:** {results.get('confidence', 0):.2f}

**Key Findings:**
{chr(10).join(f"• {finding.get('description', 'Finding')}" for finding in results.get('findings', [])[:5])}

**Recommendations:**
{chr(10).join(f"• {rec}" for rec in results.get('recommendations', [])[:5])}

*Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""

    def _format_detection_page_content(self, detection: Dict) -> str:
        """Formats detection rule as markdown content"""
        return f"""
# Detection Rule: {detection['name']}

## Description
{detection.get('description', 'Automated detection rule')}

## Query
```sql
{detection['query']}
```

## Details
- **Severity:** {detection.get('severity', 'Medium')}
- **Threshold:** {detection.get('threshold', 'N/A')}
- **Created:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

## MITRE ATT&CK Techniques
{chr(10).join(f"- {technique}" for technique in detection.get('mitre_techniques', []))}

*This page was automatically generated from a successful threat hunt.*
"""
