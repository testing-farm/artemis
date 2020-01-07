import datetime
import dataclasses
import sqlalchemy

from prometheus_client import Gauge
from prometheus_client.metrics import MetricWrapperBase
from prometheus_client.values import ValueClass

from gluetool.result import Result
from gluetool.log import ContextAdapter

from artemis import Failure, safe_db_execute, safe_call
from artemis.db import Metrics

from typing import Any, Dict, List, Optional, Tuple, cast


@dataclasses.dataclass
class MetricGauge(MetricWrapperBase):  # type: ignore
    ''' This class is supposed to be used for inserting and updating data in metrics table.
        After correctly instanciating this class and calling it's record() method, it will
        decrease and increase appropriate counter in metrics table (decreasing it for old
        state and increasing for new state) '''

    _type = 'gauge'
    _multiprocess_mode = 'all'

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Optional[List[str]] = None,
        **kwargs: Optional[Dict[Any, Any]]
    ) -> None:

        super(MetricGauge, self).__init__(name, documentation, labelnames, **kwargs)
        self.session = None  # type: sqlalchemy.orm.session.Session  # type: ignore
        self.logger = None  # type: ContextAdapter  # type: ignore
        self.poolname = None
        self.state = None
        self._metric_init()

    def __hash__(self) -> int:
        return hash((self._name, self._documentation, self._labelnames))

    def __str__(self) -> str:
        return "{}{}".format(self._name, self._labelnames)

    def _metric_init(self) -> None:
        self._value = ValueClass(
            self._type, self._name, self._name, self._labelnames, self._labelvalues,
            multiprocess_mode=self._multiprocess_mode
        )
        self._created = datetime.datetime.now()

    def _child_samples(self) -> Tuple[Any]:
        return (('', {}, self._value.get()),)

    def labels(
        self,
        session: sqlalchemy.orm.session.Session,
        logger: ContextAdapter,
        *labelvalues: Any,
    ) -> Any:
        self.session = session
        self.logger = logger
        self.labelvalues = labelvalues

        values_length = len(labelvalues)
        if values_length > 1:
            # record for given pool and state
            # poolname and new_state should be overriden with data from labelvalues
            self.poolname = labelvalues[0]
            self.state = labelvalues[1]
        elif values_length == 1:
            # record for given pool
            # poolname should be overriden with data from labelvalues
            self.poolname = labelvalues[0]
        else:
            # no labelvalues were passed, assuming it's overall counter, no db operations needed
            pass

        self._metrics[labelvalues] = super(MetricGauge, self).labels(*labelvalues)
        self._metrics[labelvalues].session = self.session
        self._metrics[labelvalues].logger = self.logger
        self._metrics[labelvalues].poolname = self.poolname
        self._metrics[labelvalues].state = self.state
        return self._metrics[labelvalues]

    def _get_db_record(self) -> Optional[Metrics]:
        query = self.session \
                .query(Metrics) \
                .filter(Metrics.poolname == self.poolname) \
                .filter(Metrics.state == self.state)

        result = cast(
            Result[Metrics, Failure],
            safe_call(query.one)
        )

        if result.is_ok:
            return cast(Metrics, result.value)

        else:
            failure = cast(Failure, result.value)

            if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
                return None

        failure.reraise()

    def _create_db_record(self) -> Result[bool, Failure]:
        if self.state:
            query = sqlalchemy \
                .insert(Metrics.__table__) \
                .values(poolname=self.poolname,
                        state=self.state)
        else:
            query = sqlalchemy \
                .insert(Metrics.__table__) \
                .values(poolname=self.poolname)

        result = safe_db_execute(self.logger, self.session, query)

        if result.is_ok:
            return result

        failure = cast(Failure, result.value)
        failure.reraise()

    def inc(self) -> Result[bool, Failure]:

        record = self._get_db_record()
        if record is None:
            # given pool and state aren't in metrics yet, insert
            result = self._create_db_record()

            if result.is_error:
                failure = cast(Failure, result.value)
                failure.reraise()

            record = self._get_db_record()

        else:
            # metric for pool and state already exists, update
            query = sqlalchemy \
                .update(Metrics.__table__) \
                .where(Metrics._id == record._id) \
                .values(count=Metrics.count + 1,
                        updated=datetime.datetime.now())

            result = safe_db_execute(self.logger, self.session, query)

        if result.is_ok:

            assert record is not None

            self._value.set(record.count)
            self.logger.info("increased value of metric {}(poolname={},state={}), to {} (record.count {})"
                             .format(self._name, self.poolname, self.state, self._value.get(), record.count))

            return Result.Ok(True)

        failure = cast(Failure, result.value)
        failure.reraise()

    def dec(self) -> Result[bool, Failure]:

        record = self._get_db_record()

        if record and record.count > 0:
            query = sqlalchemy \
                .update(Metrics.__table__) \
                .where(Metrics._id == record._id) \
                .values(count=Metrics.count - 1,
                        updated=datetime.datetime.now())

            result = safe_db_execute(self.logger, self.session, query)

            if result.is_ok:
                self._value.set(record.count)
                self.logger.info("decreased value of metric {}(poolname={},state={}), to {} (record.count {})"
                                 .format(self._name, self.poolname, self.state, self._value.get(), record.count))

                return Result.Ok(True)

            failure = cast(Failure, result.value)
            failure.reraise()

        return Result.Ok(False)

    def set(self, value: float) -> Result[bool, Failure]:

        record = self._get_db_record()

        if record is None:
            # given pool and state aren't in metrics yet, insert
            result = self._create_db_record()

            if result.is_error:
                failure = cast(Failure, result.value)
                failure.reraise()

            record = self._get_db_record()

        assert record is not None

        query = sqlalchemy \
            .update(Metrics.__table__) \
            .where(Metrics._id == record._id) \
            .values(count=value,
                    updated=datetime.datetime.now())

        result = safe_db_execute(self.logger, self.session, query)

        if result.is_ok:
            self._value.set(record.count)
            self.logger.info("set value of metric {}(poolname={},state={}), to {} (record.count {})"
                             .format(self._name, self.poolname, self.state, self._value.get(), record.count))
            return Result.Ok(True)

        failure = cast(Failure, result.value)
        failure.reraise()


GUEST_REQUESTS_ALL_COUNT = Gauge(
    "guest_requests_all_total",
    "Overall guest requests count",
)

GUEST_REQUESTS_COUNT = MetricGauge(
    "guest_requests_total",
    "Guest requests count in given pool",
    ["pool"]
)

GUEST_REQUESTS_STATE_COUNT = MetricGauge(
    "guest_requests_state_total",
    "Guest requests count in given pool by state",
    ["pool", "state"]
)

CURRENT_GUEST_REQUESTS_ALL_COUNT = Gauge(
    "current_guest_requests_all_total",
    "Overall current guest requests count",
)

CURRENT_GUEST_REQUESTS_COUNT = Gauge(
    "current_guest_requests_total",
    "Current guest requests count in given pool",
    ["pool"]
)

CURRENT_GUEST_REQUESTS_STATE_COUNT = Gauge(
    "current_guest_requests_state_total",
    "Current guest requests count in given pool by state",
    ["pool", "state"]
)
