require 'test/unit'

# require Rails testing framework
require File.dirname(__FILE__) + '/../../../../test/test_helper'

$:.unshift File.dirname(__FILE__) + '/../lib'
require File.dirname(__FILE__) + '/../init'

class WordExportTest < Test::Unit::TestCase
  XML_PARA = '<w:p><w:r><w:t>test text</w:t></w:r></w:p>'
  XML_PARA_PPROPS="<w:p><w:pPr><w:jc w:val='right'/></w:pPr><w:r><w:t>2009-02-10 00:07 GMT</w:t></w:r></w:p>"
  XML_PARA_PROPS=<<EXP
  <w:p>
    <w:pPr>
      <w:jc w:val="right"/>
    </w:pPr>
    <w:r>
      <w:rPr><w:rFonts w:ascii="Arial" w:h-ansi="Arial" w:cs="Arial"/><wx:font wx:val="Arial"/><w:sz w:val="16"/><w:sz-cs w:val="16"/></w:rPr>
      <w:t id="vulncreated">2009-02-10 00:07 GMT</w:t>
    </w:r>
  </w:p>
EXP

  # Simple test to check the paragraph formation facility. A simple text with no
  # run or paragraph attributes
  def test_simpletext_noprops
    assert_equal(XML_PARA, WordExport::Processor.word_paragraph_for('test text', {}).to_s)
  end

  def test_pprops
    pprops = [
      { :root => 'w:jc', :attributes => { 'w:val' => 'right' } }
    ]
    assert_equal(XML_PARA_PPROPS, WordExport::Processor.word_paragraph_for('2009-02-10 00:07 GMT', :pprops => pprops).to_s)
  end
end
