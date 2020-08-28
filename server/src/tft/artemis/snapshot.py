import gluetool.log


class SnapshotLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, snapshotname: str) -> None:
        super(SnapshotLogger, self).__init__(logger, {
            'ctx_snapshot_name': (11, snapshotname)
        })


class Snapshot:
    """
    Parent class of all provisioned machines. Pool drivers may create their own child classes
    to track their own internal information (e.g. cloud instance IDs) within the same object.
    """

    def __init__(
        self,
        snapshotname: str,
        guestname: str,
    ) -> None:
        self.snapshotname = snapshotname
        self.guestname = guestname

    def __repr__(self) -> str:
        return '<Snapshot: name={}, guest name={}>'.format(
            self.snapshotname,
            self.guestname
        )

    @property
    def is_promised(self) -> bool:
        raise NotImplementedError()
