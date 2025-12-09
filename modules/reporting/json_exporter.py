"""JSON export for API integration"""
import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from loguru import logger

class JSONExporter:
    def __init__(self, config):
        self.config = config
    
    async def export(self, data: Dict, output_path) -> Any:
        logger.info(f"Exporting JSON: {output_path}")
        
        try:
            # Convert data to JSON-serializable format
            json_data = self._serialize(data)
            json_data['generated_at'] = datetime.now().isoformat()
            json_data['tool'] = 'AutoPenTest'
            json_data['version'] = '1.0.0'
            
            Path(output_path).write_text(json.dumps(json_data, indent=2, default=str), encoding='utf-8')
            logger.success(f"JSON exported: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            return None
    
    def _serialize(self, obj):
        if hasattr(obj, '__dict__'):
            return {k: self._serialize(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
        elif isinstance(obj, dict):
            return {k: self._serialize(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._serialize(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        else:
            return obj
