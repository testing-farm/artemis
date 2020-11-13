import gluetool.log


class SnapshotLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, snapshotname: str) -> None:
        super(SnapshotLogger, self).__init__(logger, {
            'ctx_snapshot_name': (11, snapshotname)
        })
