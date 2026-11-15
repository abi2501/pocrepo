"""Azure Table Storage repository. Uses App Service system-assigned managed identity."""
from datetime import datetime, timezone


class PinStoreError(RuntimeError):
    pass


class PinStore:
    def __init__(self, endpoint: str, table_name: str):
        if not endpoint.startswith('https://') or not endpoint.endswith('.table.core.windows.net'):
            raise ValueError('Invalid Azure Table endpoint')
        from azure.identity import ManagedIdentityCredential
        from azure.data.tables import TableServiceClient
        self.table = TableServiceClient(endpoint=endpoint, credential=ManagedIdentityCredential()).get_table_client(table_name)

    @staticmethod
    def _entity_to_record(entity):
        if entity is None or entity.get('Status') != 'Active':
            return None
        return {
            'algorithm': entity['Algorithm'],
            'saltBase64': entity['SaltBase64'],
            'verifierBase64': entity['VerifierBase64'],
            'pinVersion': int(entity['PinVersion']),
        }

    def get(self, user_oid: str):
        from azure.core.exceptions import ResourceNotFoundError
        try:
            return self._entity_to_record(self.table.get_entity(partition_key='PIN', row_key=user_oid.lower()))
        except ResourceNotFoundError:
            return None

    def get_active_for_users(self, user_oids: list[str]) -> dict[str, dict]:
        """Load active verifiers for eligible directory users; never return unrelated records."""
        wanted = {str(oid).lower() for oid in user_oids}
        if not wanted:
            return {}
        # Query only the PIN partition (Azure Table handles page iteration).
        entities = self.table.query_entities(query_filter="PartitionKey eq 'PIN'")
        found = {}
        for entity in entities:
            oid = str(entity.get('RowKey', '')).lower()
            if oid in wanted:
                record = self._entity_to_record(entity)
                if record is not None:
                    found[oid] = record
        return found

    def enroll_first_time(self, user_oid: str, verifier: dict):
        """Create-only enrollment; no unauthenticated overwrite or silent reset."""
        from azure.core.exceptions import ResourceExistsError
        entity = {'PartitionKey': 'PIN', 'RowKey': user_oid.lower(),
                  'Algorithm': verifier['algorithm'], 'SaltBase64': verifier['saltBase64'],
                  'VerifierBase64': verifier['verifierBase64'], 'PinVersion': 1,
                  'Status': 'Active', 'UpdatedAtUtc': datetime.now(timezone.utc).isoformat()}
        try:
            self.table.create_entity(entity=entity)
        except ResourceExistsError as exc:
            raise PinAlreadyEnrolled('PIN already enrolled; reset requires a separate controlled flow') from exc
        return 1

    def credential_status(self, user_oid: str):
        from azure.core.exceptions import ResourceNotFoundError
        try:
            entity = self.table.get_entity(partition_key='PIN', row_key=user_oid.lower())
        except ResourceNotFoundError:
            return {'enrolled': False, 'pinVersion': None}
        return {'enrolled': entity.get('Status') == 'Active', 'pinVersion': int(entity.get('PinVersion', 0))}


class PinAlreadyEnrolled(PinStoreError):
    pass
