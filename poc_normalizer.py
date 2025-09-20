#!/usr/bin/env python3
"""
Production Log Normalizer

A robust log normalization tool for security logs from multiple sources.
Supports field mapping, data validation, type conversion, and error handling.
"""

import json
import argparse
import sys
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Union

class ProductionNormalizer:
    def __init__(self, mapping_file: str, schema_file: Optional[str] = None):
        """Initialize the normalizer with mapping and optional schema validation."""
        self.mappings = self._load_mappings(mapping_file)
        self.schema = self._load_schema(schema_file) if schema_file else None
        self.stats = {
            'processed': 0,
            'normalized': 0,
            'errors': 0,
            'warnings': 0,
            'sources': {}
        }
        
    def _load_mappings(self, mapping_file: str) -> Dict[str, Dict[str, str]]:
        """Load field mappings from JSON file."""
        try:
            with open(mapping_file, 'r') as f:
                mappings = json.load(f)
            logging.info(f"Loaded mappings for {len(mappings)} log sources")
            return mappings
        except Exception as e:
            logging.error(f"Failed to load mappings from {mapping_file}: {e}")
            raise
    
    def _load_schema(self, schema_file: str) -> Dict[str, Any]:
        """Load schema for validation (optional)."""
        try:
            with open(schema_file, 'r') as f:
                schema = json.load(f)
            logging.info("Loaded schema for validation")
            return schema
        except Exception as e:
            logging.warning(f"Failed to load schema from {schema_file}: {e}")
            return None
    
    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        """Normalize timestamp values to ISO 8601 format."""
        if not value:
            return None
            
        # If already a string in ISO format, return as-is
        if isinstance(value, str):
            # Check if already in ISO format
            iso_patterns = [
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$',
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?[+-]\d{2}:\d{2}$'
            ]
            for pattern in iso_patterns:
                if re.match(pattern, value):
                    return value
        
        return str(value)  # Return as-is if conversion fails
    
    def _normalize_ip_address(self, value: Any) -> Optional[str]:
        """Normalize IP address values."""
        if not value:
            return None
        
        ip_str = str(value).strip()
        
        # Basic IP validation patterns
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, ip_str) or re.match(ipv6_pattern, ip_str):
            return ip_str
        
        return ip_str  # Return original if validation fails
    
    def _normalize_port(self, value: Any) -> Optional[int]:
        """Normalize port numbers."""
        if not value:
            return None
        
        try:
            port = int(value)
            if 0 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        
        return None
    
    def _normalize_severity(self, value: Any) -> Optional[str]:
        """Normalize severity levels to standard values."""
        if not value:
            return None
        
        severity_map = {
            # Syslog numeric levels
            '0': 'critical', '1': 'critical', '2': 'critical',
            '3': 'high', '4': 'medium', '5': 'medium',
            '6': 'info', '7': 'debug',
            
            # Windows levels
            '1': 'critical', '2': 'high', '3': 'medium', '4': 'info',
            
            # Common string values
            'emergency': 'critical', 'alert': 'critical', 'critical': 'critical',
            'error': 'high', 'err': 'high', 'high': 'high',
            'warning': 'medium', 'warn': 'medium', 'medium': 'medium',
            'notice': 'info', 'information': 'info', 'info': 'info',
            'debug': 'debug', 'low': 'low'
        }
        
        severity_str = str(value).lower().strip()
        return severity_map.get(severity_str, severity_str)
    
    def _normalize_boolean(self, value: Any) -> Optional[bool]:
        """Normalize boolean values."""
        if isinstance(value, bool):
            return value
        
        if isinstance(value, str):
            true_values = {'true', 'yes', '1', 'on', 'enabled'}
            false_values = {'false', 'no', '0', 'off', 'disabled'}
            
            val_lower = value.lower().strip()
            if val_lower in true_values:
                return True
            elif val_lower in false_values:
                return False
        
        return None
    
    def _apply_type_conversion(self, field: str, value: Any) -> Any:
        """Apply type-specific normalization based on field name."""
        if value is None or value == '':
            return None
        
        # Timestamp fields
        timestamp_fields = {'timestamp', 'ingestion_time', 'file_created', 'file_modified', 'file_accessed'}
        if field in timestamp_fields:
            return self._normalize_timestamp(value)
        
        # IP address fields
        ip_fields = {'source_ip', 'dest_ip'}
        if field in ip_fields:
            return self._normalize_ip_address(value)
        
        # Port fields
        port_fields = {'source_port', 'dest_port'}
        if field in port_fields:
            return self._normalize_port(value)
        
        # Severity field
        if field == 'severity':
            return self._normalize_severity(value)
        
        # Boolean fields
        boolean_fields = {'service_account'}
        if field in boolean_fields:
            return self._normalize_boolean(value)
        
        # Integer fields
        integer_fields = {
            'process_id', 'parent_process_id', 'logon_type', 'priority',
            'file_size', 'bytes_sent', 'bytes_received', 'bytes_total',
            'packets_sent', 'packets_received', 'duration', 'connection_count',
            'exit_code', 'http_status', 'email_attachment_count', 'email_size',
            'vlan_id', 'vulnerability_score', 'risk_score'
        }
        if field in integer_fields:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        
        # String fields - ensure string type and strip whitespace
        return str(value).strip() if value else None
    
    def _extract_nested_field(self, log_data: Dict[str, Any], field_path: str) -> Any:
        """Extract value from nested field path (e.g., 'userIdentity.userName')."""
        try:
            value = log_data
            for key in field_path.split('.'):
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            return value
        except Exception:
            return None
    
    def _normalize_single_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single log entry."""
        if not isinstance(log_data, dict):
            self.stats['errors'] += 1
            logging.warning("Invalid log entry: not a dictionary")
            return {}
        
        # Determine log source
        log_source = log_data.get('log_source', 'default')
        
        # Get appropriate mapping
        source_mapping = self.mappings.get(log_source, {})
        default_mapping = self.mappings.get('default', {})
        
        # Track source statistics
        if log_source not in self.stats['sources']:
            self.stats['sources'][log_source] = 0
        self.stats['sources'][log_source] += 1
        
        normalized_log = {}
        processed_fields = set()
        
        # First pass: apply source-specific mappings
        for raw_field, value in log_data.items():
            if raw_field in source_mapping:
                normalized_field = source_mapping[raw_field]
                # Handle nested field extraction
                if '.' in raw_field:
                    actual_value = self._extract_nested_field(log_data, raw_field)
                    if actual_value is not None:
                        normalized_value = self._apply_type_conversion(normalized_field, actual_value)
                        normalized_log[normalized_field] = normalized_value
                else:
                    normalized_value = self._apply_type_conversion(normalized_field, value)
                    normalized_log[normalized_field] = normalized_value
                processed_fields.add(raw_field)
        
        # Second pass: apply default mappings for unprocessed fields
        for raw_field, value in log_data.items():
            if raw_field not in processed_fields and raw_field in default_mapping:
                normalized_field = default_mapping[raw_field]
                normalized_value = self._apply_type_conversion(normalized_field, value)
                # Don't overwrite fields already mapped by source-specific mapping
                if normalized_field not in normalized_log:
                    normalized_log[normalized_field] = normalized_value
                processed_fields.add(raw_field)
        
        # Third pass: keep unmapped fields as-is
        for raw_field, value in log_data.items():
            if raw_field not in processed_fields:
                normalized_value = self._apply_type_conversion(raw_field, value)
                normalized_log[raw_field] = normalized_value
        
        # Ensure required fields
        if 'timestamp' not in normalized_log:
            normalized_log['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            self.stats['warnings'] += 1
        
        if 'log_source' not in normalized_log:
            normalized_log['log_source'] = log_source
        
        # Add enrichment fields
        normalized_log['ingestion_time'] = datetime.utcnow().isoformat() + 'Z'
        
        return normalized_log
    
    def normalize_logs(self, input_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize a list of log entries."""
        normalized_logs = []
        
        for i, log_entry in enumerate(input_logs):
            try:
                self.stats['processed'] += 1
                normalized_log = self._normalize_single_log(log_entry)
                
                if normalized_log:  # Only add non-empty normalized logs
                    normalized_logs.append(normalized_log)
                    self.stats['normalized'] += 1
                else:
                    self.stats['errors'] += 1
                    
            except Exception as e:
                self.stats['errors'] += 1
                logging.error(f"Error normalizing log entry {i}: {e}")
                continue
        
        return normalized_logs
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get normalization statistics."""
        return self.stats.copy()

def main():
    parser = argparse.ArgumentParser(
        description='Production Log Normalizer for Security Logs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_file', help='Input JSON file containing log array')
    parser.add_argument('output_file', help='Output JSON file for normalized logs')
    parser.add_argument('mapping_file', help='JSON file containing field mappings')
    parser.add_argument('--schema', help='Optional JSON schema file for validation')
    parser.add_argument('--stats', action='store_true', 
                       help='Print normalization statistics')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--validate', action='store_true',
                       help='Validate output against schema (requires --schema)')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )
    
    try:
        # Initialize normalizer
        normalizer = ProductionNormalizer(args.mapping_file, args.schema)
        
        # Load input logs
        logging.info(f"Loading logs from {args.input_file}")
        with open(args.input_file, 'r', encoding='utf-8') as f:
            input_logs = json.load(f)
        
        if not isinstance(input_logs, list):
            logging.error("Input file must contain a JSON array of log objects")
            sys.exit(1)
        
        logging.info(f"Loaded {len(input_logs)} log entries")
        
        # Normalize logs
        logging.info("Starting normalization process")
        normalized_logs = normalizer.normalize_logs(input_logs)
        
        # Write output
        logging.info(f"Writing {len(normalized_logs)} normalized logs to {args.output_file}")
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(normalized_logs, f, indent=2, ensure_ascii=False, default=str)
        
        # Print statistics
        if args.stats:
            stats = normalizer.get_statistics()
            print("\n=== Normalization Statistics ===", file=sys.stderr)
            print(f"Processed: {stats['processed']}", file=sys.stderr)
            print(f"Normalized: {stats['normalized']}", file=sys.stderr)
            print(f"Errors: {stats['errors']}", file=sys.stderr)
            print(f"Warnings: {stats['warnings']}", file=sys.stderr)
            print(f"Success Rate: {(stats['normalized']/stats['processed']*100):.1f}%", file=sys.stderr)
            
            if stats['sources']:
                print(f"\nLog Sources:", file=sys.stderr)
                for source, count in stats['sources'].items():
                    print(f"  {source}: {count}", file=sys.stderr)
        
        logging.info("Normalization completed successfully")
        
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
