

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


class Database:
    def __init__(self, model, echo=True):
        self.__engine = create_engine("sqlite:///./cvedb.db", echo=echo)
        Session = sessionmaker(bind=self.__engine)
        model.metadata.create_all(self.__engine)
        self.__session = Session()

    def close(self):
        self.__session.close()

    def commit(self):
        self.__session.commit()

    def get_session(self):
        return self.__session

    def get_record_by_attribute(self, model, attribute, value):
        records = self.__session.query(model).filter(getattr(model, attribute) == value).all()
        return records
