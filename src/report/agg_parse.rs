use std::io::BufRead;
use std::str::FromStr;

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use super::{
    Alignment, DateRange, Disposition, Extension, Feedback, PolicyPublished, Record, ReportMetadata,
};

impl Feedback {
    pub fn parse(report: &[u8]) -> Result<Self, String> {
        let mut version = 0;
        let mut report_metadata = None;
        let mut policy_published = None;
        let mut record = Vec::new();
        let mut extensions = Vec::new();

        let mut reader = Reader::from_reader(report);
        reader.trim_text(true);

        let mut buf = Vec::with_capacity(128);
        let mut found_feedback = false;

        while let Some(tag) = reader.next_tag(&mut buf)? {
            match tag.name().as_ref() {
                b"feedback" if !found_feedback => {
                    found_feedback = true;
                }
                b"version" if found_feedback => {
                    version = reader.next_value(&mut buf)?.unwrap_or(0);
                }
                b"report_metadata" if found_feedback => {
                    report_metadata = ReportMetadata::parse(&mut reader, &mut buf)?.into();
                }
                b"policy_published" if found_feedback => {
                    policy_published = PolicyPublished::parse(&mut reader, &mut buf)?.into();
                }
                b"record" if found_feedback => {
                    record.push(Record::parse(&mut reader, &mut buf)?);
                }
                b"extensions" if found_feedback => {
                    if let Some(extension) = Extension::parse(&mut reader, &mut buf)? {
                        extensions.push(extension);
                    }
                }
                b"" => {}
                other if !found_feedback => {
                    return Err(format!(
                        "Unexpected tag {} at position {}.",
                        String::from_utf8_lossy(other),
                        reader.buffer_position()
                    ));
                }
                _ => (),
            }
        }

        Ok(Feedback {
            version,
            report_metadata: report_metadata.ok_or("Missing feedback/report_metadata tag.")?,
            policy_published: policy_published.ok_or("Missing feedback/policy_published tag.")?,
            record,
            extensions,
        })
    }
}

impl ReportMetadata {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut org_name = String::new();
        let mut email = String::new();
        let mut extra_contact_info = None;
        let mut report_id = String::new();
        let mut date_range = None;
        let mut error = Vec::new();

        while let Some(tag) = reader.next_tag(buf)? {
            match tag.name().as_ref() {
                b"org_name" => {
                    org_name = reader.next_value::<String>(buf)?.unwrap_or_default();
                }
                b"email" => {
                    email = reader.next_value::<String>(buf)?.unwrap_or_default();
                }
                b"extra_contact_info" => {
                    extra_contact_info = reader.next_value::<String>(buf)?;
                }
                b"report_id" => {
                    report_id = reader.next_value::<String>(buf)?.unwrap_or_default();
                }
                b"date_range" => {
                    date_range = DateRange::parse(reader, buf)?.into();
                }
                b"error" => {
                    if let Some(err) = reader.next_value::<String>(buf)? {
                        error.push(err);
                    }
                }
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            }
        }

        Ok(ReportMetadata {
            org_name,
            email,
            extra_contact_info,
            report_id,
            date_range: date_range.unwrap_or_default(),
            error,
        })
    }
}

impl DateRange {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut begin = 0;
        let mut end = 0;

        while let Some(tag) = reader.next_tag(buf)? {
            match tag.name().as_ref() {
                b"begin" => {
                    begin = reader.next_value(buf)?.unwrap_or_default();
                }
                b"end" => {
                    end = reader.next_value(buf)?.unwrap_or_default();
                }
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            }
        }

        Ok(DateRange { begin, end })
    }
}

impl PolicyPublished {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut domain = String::new();
        let mut version_published = None;
        let mut adkim = Alignment::Unspecified;
        let mut aspf = Alignment::Unspecified;
        let mut p = Disposition::Unspecified;
        let mut sp = Disposition::Unspecified;
        let mut testing = false;
        let mut fo = None;

        while let Some(tag) = reader.next_tag(buf)? {
            match tag.name().as_ref() {
                b"domain" => {
                    domain = reader.next_value::<String>(buf)?.unwrap_or_default();
                }
                b"version_published" => {
                    version_published = reader.next_value(buf)?;
                }
                b"adkim" => {
                    adkim = reader.next_value(buf)?.unwrap_or(Alignment::Unspecified);
                }
                b"aspf" => {
                    aspf = reader.next_value(buf)?.unwrap_or(Alignment::Unspecified);
                }
                b"p" => {
                    p = reader.next_value(buf)?.unwrap_or(Disposition::Unspecified);
                }
                b"sp" => {
                    sp = reader.next_value(buf)?.unwrap_or(Disposition::Unspecified);
                }
                b"testing" => {
                    testing = reader
                        .next_value::<String>(buf)?
                        .map_or(false, |s| s.eq_ignore_ascii_case("y"));
                }
                b"fo" => {
                    fo = reader.next_value::<String>(buf)?;
                }
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            }
        }

        Ok(PolicyPublished {
            domain,
            version_published,
            adkim,
            aspf,
            p,
            sp,
            testing,
            fo,
        })
    }
}

impl Extension {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Option<Self>, String> {
        let mut name = String::new();
        let mut definition = String::new();
        let mut extension = None;

        while let Some(tag) = reader.next_tag(buf)? {
            match tag.name().as_ref() {
                b"extension" => {
                    if let Ok(Some(attr)) = tag.try_get_attribute("name") {
                        if let Ok(attr) = attr.unescape_value() {
                            name = attr.to_string();
                        }
                    }
                    if let Ok(Some(attr)) = tag.try_get_attribute("definition") {
                        if let Ok(attr) = attr.unescape_value() {
                            definition = attr.to_string();
                        }
                    }

                    extension = reader.next_value(buf)?;
                }
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            }
        }

        Ok(if !name.is_empty() {
            Some(Extension {
                extension,
                name,
                definition,
            })
        } else {
            None
        })
    }
}

impl Record {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut begin = 0;
        let mut end = 0;

        while let Some(tag) = reader.next_tag(buf)? {
            match tag.name().as_ref() {
                b"begin" => {
                    begin = reader.next_value(buf)?.unwrap_or_default();
                }
                b"end" => {
                    end = reader.next_value(buf)?.unwrap_or_default();
                }
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            }
        }

        Ok(Record {
            row: todo!(),
            identifiers: todo!(),
            auth_results: todo!(),
        })
    }
}

impl FromStr for Disposition {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.as_bytes() {
            b"none" => Disposition::None,
            b"quarantine" => Disposition::Quarantine,
            b"reject" => Disposition::Reject,
            _ => Disposition::Unspecified,
        })
    }
}

impl FromStr for Alignment {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.as_bytes().first() {
            Some(b'r') => Alignment::Relaxed,
            Some(b's') => Alignment::Simple,
            _ => Alignment::Unspecified,
        })
    }
}

trait ReaderHelper {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String>;
    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String>;
    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String>;
}

impl<R: BufRead> ReaderHelper for Reader<R> {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String> {
        match self.read_event_into(buf) {
            Ok(Event::Start(e)) => Ok(Some(e)),
            Ok(Event::End(_)) | Ok(Event::Eof) => Ok(None),
            Err(e) => Err(format!(
                "Error at position {}: {:?}",
                self.buffer_position(),
                e
            )),
            _ => Ok(Some(BytesStart::new(""))),
        }
    }

    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String> {
        let mut value = None;
        loop {
            match self.read_event_into(buf) {
                Ok(Event::Text(e)) => {
                    let value_ = e.unescape().map_err(|err| {
                        format!(
                            "Failed to unescape value at {}: {}",
                            self.buffer_position(),
                            err
                        )
                    })?;

                    value = T::from_str(value_.as_ref())
                        .map_err(|_| {
                            format!(
                                "Failed to parse value {:?} at {}.",
                                value_,
                                self.buffer_position(),
                            )
                        })?
                        .into();
                }
                Ok(Event::End(_)) => {
                    break;
                }
                Ok(Event::Start(e)) => {
                    return Err(format!(
                        "Expected value, found unexpected tag {} at position {}.",
                        String::from_utf8_lossy(e.name().as_ref()),
                        self.buffer_position()
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ))
                }
                _ => (),
            }
        }

        Ok(value)
    }

    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String> {
        let mut tag_count = 0;
        loop {
            match self.read_event_into(buf) {
                Ok(Event::End(_)) => {
                    if tag_count == 0 {
                        break;
                    } else {
                        tag_count -= 1;
                    }
                }
                Ok(Event::Start(_)) => {
                    tag_count += 1;
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ))
                }
                _ => (),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{fs, path::PathBuf};

    #[test]
    fn dmarc_aggregate_report_parse() {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("dmarc-agg-report");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            println!("file {}", file_name.to_str().unwrap());
            let mut reader = Reader::from_file(file_name).unwrap();
            reader.trim_text(true);

            let mut count = 0;
            let mut txt = Vec::new();
            let mut buf = Vec::new();

            // The `Reader` does not implement `Iterator` because it outputs borrowed data (`Cow`s)
            loop {
                // NOTE: this is the generic case when we don't know about the input BufRead.
                // when the input is a &str or a &[u8], we don't actually need to use another
                // buffer, we could directly call `reader.read_event()`
                match reader.read_event_into(&mut buf) {
                    Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
                    // exits the loop when reaching end of file
                    Ok(Event::Eof) => break,

                    Ok(Event::Start(e)) => {
                        println!("start: {}", std::str::from_utf8(e.name().as_ref()).unwrap())
                    }
                    Ok(Event::End(e)) => {
                        println!("end: {}", std::str::from_utf8(e.name().as_ref()).unwrap())
                    }
                    Ok(Event::Text(e)) => txt.push(e.unescape().unwrap().into_owned()),

                    // There are several other `Event`s we do not consider here
                    _ => (),
                }
                // if we don't keep a borrow elsewhere, we can clear the buffer to keep memory usage low
                buf.clear();
            }
        }
    }
}
