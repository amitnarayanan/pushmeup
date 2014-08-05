require 'socket'
require 'openssl'
require 'json'

module APNS

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195
  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pems   = nil # this should be a hash of target devices and paths of pem files, not pem's contents
  @passes = nil
  
  @persistent = false
  @mutex = Mutex.new
  @retries = 3 # TODO: check if we really need this
  
  @sock = nil
  @ssl = nil
  
  class << self
    attr_accessor :host, :pems, :port, :passes
  end
  
  def self.start_persistence
    @persistent = true
  end
  
  def self.stop_persistence
    @persistent = false
    
    @ssl.close
    @sock.close
  end
  
  def self.send_notification(device_token, message, target)
    n = APNS::Notification.new(device_token, message)
    self.send_notifications([n], target)
  end
  
  def self.send_notifications(notifications, target)
    raise "The path to your pem file is not set. (APNS.pems = { target1: '/path/to/cert1.pem', target2: '/path/to/cert2.pem' }" unless self.pems
    raise "The path to your #{target} pem file does not exist!" unless File.exist?(self.pems[target])

    @mutex.synchronize do
      self.with_connection(target) do
        notifications.each do |n|
          @ssl.write(n.packaged_notification)
        end
      end
    end
  end
  
  def self.feedback(target)
    raise "The path to your pem file is not set. (APNS.pems = { target1: '/path/to/cert1.pem', target2: '/path/to/cert2.pem' }" unless self.pems
    raise "The path to your #{target} pem file does not exist!" unless File.exist?(self.pems[target])

    sock, ssl = self.feedback_connection(target)

    apns_feedback = []

    while line = ssl.read(38)   # Read lines from the socket
      line.strip!
      f = line.unpack('N1n1H140')
      apns_feedback << { :timestamp => Time.at(f[0]), :token => f[2] }
    end

    ssl.close
    sock.close

    return apns_feedback
  end
  
protected
  
  def self.with_connection(target)
    attempts = 1
  
    begin      
      # If no @ssl is created or if @ssl is closed we need to start it
      if @ssl.nil? || @sock.nil? || @ssl.closed? || @sock.closed?
        @sock, @ssl = self.open_connection(self.pems[target], self.passes[target], self.host, self.port)
      end
    
      yield
    
    rescue StandardError, Errno::EPIPE
      raise unless attempts < @retries
    
      @ssl.close
      @sock.close
    
      attempts += 1
      retry
    end
  
    # Only force close if not persistent
    unless @persistent
      @ssl.close
      @ssl = nil
      @sock.close
      @sock = nil
    end
  end
  
  def self.open_connection(pem, pass, host, port)
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)

    sock         = TCPSocket.new(host, port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end
  
  def self.feedback_connection(target)
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pems[target]))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pems[target]), self.passes[target])
    
    fhost = self.host.gsub('gateway','feedback')
    
    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect

    return sock, ssl
  end
  
end
